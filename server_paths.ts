/**
 * Yashi — path & secret resolution.
 *
 * Separates read-only *code/asset* locations (shipped with the app) from the
 * writable *data* location (per-user, survives reinstalls). In development both
 * collapse to the project root, so existing behaviour is unchanged. When the
 * packaged Electron app launches the backend it sets YASHI_DATA_DIR to a
 * writable folder under ~/Library/Application Support/Yashi, because the app
 * bundle (/Applications) is read-only.
 *
 * The Gemini API key is NOT shipped with the app. Each user supplies their own
 * on first run; it is stored encrypted in the per-user data dir (never returned
 * to the frontend).
 */

import fs from "fs";
import path from "path";
import crypto from "crypto";

/** Writable per-user data directory. Falls back to cwd in development. */
export const DATA_DIR: string =
  process.env.YASHI_DATA_DIR || process.env.VEXA_DATA_DIR || process.cwd();

try {
  fs.mkdirSync(DATA_DIR, { recursive: true });
} catch {
  /* already exists / best-effort */
}

/** Absolute path to a file inside the writable data directory. */
export function dataFile(name: string): string {
  return path.join(DATA_DIR, name);
}

// ---------------------------------------------------------------------------
// Encryption utilities for secrets.json
// ---------------------------------------------------------------------------
const SECRETS_FILE = dataFile("secrets.json.enc");
const LEGACY_SECRETS_FILE = dataFile("secrets.json"); // For migration

/** Derive a machine-specific encryption key from stable machine identifiers. */
function getEncryptionKey(): Buffer {
  // Use machine ID (from /etc/machine-id or /var/lib/dbus/machine-id on Linux,
  // or IOPlatformUUID on macOS) combined with the data directory path.
  // This ensures the key is unique per machine+user but not stored anywhere.
  let machineId = "";
  try {
    if (process.platform === "darwin") {
      // macOS: use IOPlatformUUID via ioreg
      const { execSync } = require("child_process");
      machineId = execSync("ioreg -rd1 -c IOPlatformExpertDevice | grep IOPlatformUUID", { encoding: "utf-8", timeout: 2000 })
        .split('"')[3] || "";
    } else if (process.platform === "linux") {
      // Linux: /etc/machine-id or /var/lib/dbus/machine-id
      const candidates = ["/etc/machine-id", "/var/lib/dbus/machine-id"];
      for (const f of candidates) {
        if (fs.existsSync(f)) {
          machineId = fs.readFileSync(f, "utf-8").trim();
          break;
        }
      }
    } else if (process.platform === "win32") {
      // Windows: MachineGuid from registry
      const { execSync } = require("child_process");
      machineId = execSync('reg query HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography /v MachineGuid', { encoding: "utf-8", timeout: 2000 })
        .split("\\s+")?.pop()?.trim() || "";
    }
  } catch {
    // Fallback: use a hash of the data directory path
    machineId = DATA_DIR;
  }
  
  // Combine machine ID with data directory for user-specific derivation
  const input = `${machineId}:${DATA_DIR}:yashi-secrets-v1`;
  return crypto.createHash("sha256").update(input).digest();
}

/** Legacy key derivation for seamless migration from older installations. */
function getLegacyEncryptionKey(): Buffer {
  let machineId = DATA_DIR;
  try {
    if (process.platform === "darwin") {
      const { execSync } = require("child_process");
      machineId = execSync("ioreg -rd1 -c IOPlatformExpertDevice | grep IOPlatformUUID", { encoding: "utf-8", timeout: 2000 })
        .split('"')[3] || "";
    } else if (process.platform === "linux") {
      const candidates = ["/etc/machine-id", "/var/lib/dbus/machine-id"];
      for (const f of candidates) {
        if (fs.existsSync(f)) {
          machineId = fs.readFileSync(f, "utf-8").trim();
          break;
        }
      }
    } else if (process.platform === "win32") {
      const { execSync } = require("child_process");
      machineId = execSync('reg query HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography /v MachineGuid', { encoding: "utf-8", timeout: 2000 })
        .split("\\s+")?.pop()?.trim() || "";
    }
  } catch {
    machineId = DATA_DIR;
  }
  const input = `${machineId}:${DATA_DIR}:vexa-secrets-v1`;
  return crypto.createHash("sha256").update(input).digest();
}

/** Encrypt data using AES-256-GCM. Returns base64 string: iv:authTag:ciphertext */
function encrypt(data: string): string {
  const key = getEncryptionKey();
  const iv = crypto.randomBytes(12); // 96-bit IV for GCM
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(data, "utf-8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return `${iv.toString("base64")}:${authTag.toString("base64")}:${ciphertext.toString("base64")}`;
}

/** Decrypt data from base64 string: iv:authTag:ciphertext (with fallback to legacy key) */
function decrypt(encrypted: string): string | null {
  const parts = encrypted.split(":");
  if (parts.length !== 3) return null;

  for (const keyFn of [getEncryptionKey, getLegacyEncryptionKey]) {
    try {
      const key = keyFn();
      const iv = Buffer.from(parts[0], "base64");
      const authTag = Buffer.from(parts[1], "base64");
      const ciphertext = Buffer.from(parts[2], "base64");
      const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
      decipher.setAuthTag(authTag);
      const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      return plaintext.toString("utf-8");
    } catch {
      // try next key derivation
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Gemini API key store (encrypted secrets.json.enc in the data dir).
// ---------------------------------------------------------------------------

interface Secrets {
  geminiApiKey?: string;
  supabaseUrl?: string;
  supabaseAnonKey?: string;
  groqApiKey?: string;
  openRouterApiKey?: string;
  nvidiaApiKey?: string;
}

function readSecrets(): Secrets {
  // Try encrypted file first
  if (fs.existsSync(SECRETS_FILE)) {
    try {
      const encrypted = fs.readFileSync(SECRETS_FILE, "utf-8").trim();
      const decrypted = decrypt(encrypted);
      if (decrypted) {
        return JSON.parse(decrypted) as Secrets;
      }
    } catch {
      /* corrupt — fall through to legacy migration */
    }
  }
  
  // Migration from legacy unencrypted secrets.json
  if (fs.existsSync(LEGACY_SECRETS_FILE)) {
    try {
      const legacy = JSON.parse(fs.readFileSync(LEGACY_SECRETS_FILE, "utf-8")) as Secrets;
      // Write to new encrypted format
      writeSecrets(legacy);
      // Remove legacy file
      try { fs.unlinkSync(LEGACY_SECRETS_FILE); } catch {}
      return legacy;
    } catch {
      /* corrupt — treat as empty */
    }
  }
  
  return {};
}

function writeSecrets(secrets: Secrets): void {
  const encrypted = encrypt(JSON.stringify(secrets));
  fs.writeFileSync(SECRETS_FILE, encrypted, "utf-8");
  try {
    fs.chmodSync(SECRETS_FILE, 0o600); // owner-only
  } catch {
    /* best-effort */
  }
}

/**
 * Resolve the active Gemini API key.
 * Priority: user-entered key (secrets.json) → environment (.env, dev only).
 */
export function getGeminiApiKey(): string | undefined {
  const stored = readSecrets().geminiApiKey?.trim();
  if (stored) return stored;
  const env = process.env.GEMINI_API_KEY?.trim();
  return env || undefined;
}

export function getSupabaseConfig(): { url?: string; key?: string } {
  const secrets = readSecrets();
  return {
    url: secrets.supabaseUrl?.trim() || process.env.SUPABASE_URL?.trim(),
    key: secrets.supabaseAnonKey?.trim() || process.env.SUPABASE_ANON_KEY?.trim(),
  };
}

export function setSupabaseConfig(url: string, key: string): void {
  const current = readSecrets();
  current.supabaseUrl = url.trim();
  current.supabaseAnonKey = key.trim();
  writeSecrets(current);
}

export function getGroqApiKey(): string | undefined {
  const stored = readSecrets().groqApiKey?.trim();
  if (stored) return stored;
  return process.env.GROQ_API_KEY?.trim();
}

export function setGroqApiKey(key: string): void {
  const current = readSecrets();
  current.groqApiKey = key.trim();
  writeSecrets(current);
}

export function getOpenRouterApiKey(): string | undefined {
  const stored = readSecrets().openRouterApiKey?.trim();
  if (stored) return stored;
  return process.env.OPENROUTER_API_KEY?.trim();
}

export function setOpenRouterApiKey(key: string): void {
  const current = readSecrets();
  current.openRouterApiKey = key.trim();
  writeSecrets(current);
}

export function getNvidiaApiKey(): string | undefined {
  const stored = readSecrets().nvidiaApiKey?.trim();
  if (stored) return stored;
  return process.env.NVIDIA_API_KEY?.trim();
}

export function setNvidiaApiKey(key: string): void {
  const current = readSecrets();
  current.nvidiaApiKey = key.trim();
  writeSecrets(current);
}

export function hasNvidiaApiKey(): boolean {
  return Boolean(getNvidiaApiKey());
}

/** Whether any usable key is configured (without revealing it). */
export function hasGeminiApiKey(): boolean {
  return Boolean(getGeminiApiKey());
}

/** Persist a user-supplied key to the per-user secrets file. */
export function setGeminiApiKey(key: string): void {
  const trimmed = (key || "").trim();
  if (!trimmed) throw new Error("API key must not be empty.");
  const current = readSecrets();
  current.geminiApiKey = trimmed;
  writeSecrets(current);
}

/** Remove the stored key (used by "reset"/sign-out flows). */
export function clearGeminiApiKey(): void {
  const current = readSecrets();
  delete current.geminiApiKey;
  writeSecrets(current);
}
