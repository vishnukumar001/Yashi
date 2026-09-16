/**
 * Yashi Provider Types — Multi-provider API switching (Feature 4).
 *
 * Defines interfaces for the three supported AI providers:
 *   1. Gemini (Live API — real-time bidirectional audio)
 *   2. OpenRouter (Chat Completions API — text-based)
 *   3. Groq (Chat Completions API — text-based)
 *
 * Each provider has a type (live vs text) and a priority for automatic failover.
 */

/** Supported AI provider identifiers. */
export type ProviderType = "gemini" | "openrouter" | "groq" | "nvidia";

/** How the provider communicates — audio streaming or text chat. */
export type ProviderMode = "live" | "text";

/** Configuration needed to connect to a provider. */
export interface ProviderConfig {
  type: ProviderType;
  mode: ProviderMode;
  apiKey: string;
  model: string;
  endpoint: string;
}

/** Runtime health/status of a provider. */
export interface ProviderStatus {
  type: ProviderType;
  mode: ProviderMode;
  healthy: boolean;
  latencyMs: number | null;
  lastError: string | null;
  lastCheckAt: string | null;
}

/** Event sent to the client when a provider switch occurs. */
export interface ProviderSwitchEvent {
  type: "provider_switch";
  previous: ProviderType;
  current: ProviderType;
  mode: ProviderMode;
  reason: string;
}

/** Provider priority order — first element is the primary. */
export const PROVIDER_PRIORITY: ProviderType[] = ["gemini", "nvidia", "openrouter", "groq"];

/** Default model names for each provider. */
export const DEFAULT_MODELS: Record<ProviderType, string> = {
  gemini: "gemini-3.5-flash-lite",
  openrouter: "openai/gpt-4o-mini",
  groq: "llama-3.1-8b-instant",
  nvidia: "nvidia/nemotron-3-ultra-550b-a55b",
};

/** API endpoints for each provider. */
export const PROVIDER_ENDPOINTS: Record<ProviderType, string> = {
  gemini: "", // Gemini Live uses the SDK, not an HTTP endpoint
  openrouter: "https://openrouter.ai/api/v1/chat/completions",
  groq: "https://api.groq.com/openai/v1/chat/completions",
  nvidia: "https://integrate.api.nvidia.com/v1",
};

/** Human-readable display names. */
export const PROVIDER_DISPLAY_NAMES: Record<ProviderType, string> = {
  gemini: "Gemini",
  openrouter: "OpenRouter",
  groq: "Groq",
  nvidia: "NVIDIA Nemotron",
};

/**
 * Build a ProviderConfig from a provider type and API key.
 * Uses default model and endpoint for the given provider.
 */
export function buildProviderConfig(
  type: ProviderType,
  apiKey: string,
  model?: string,
): ProviderConfig {
  return {
    type,
    mode: type === "gemini" ? "live" : "text",
    apiKey,
    model: model || DEFAULT_MODELS[type],
    endpoint: PROVIDER_ENDPOINTS[type],
  };
}

/**
 * Classify an error from a provider to determine if it warrants a failover.
 * Returns true if the error indicates the provider is temporarily unusable.
 */
export function isFailoverError(error: unknown): boolean {
  const msg = String(
    (error as any)?.message || (error as any)?.toString?.() || "",
  ).toLowerCase();

  return (
    /quota|rate.?limit|429|503|timeout|unavailable|overloaded|resource.?exhausted/i.test(
      msg,
    ) ||
    /invalid.?response|empty.?response|no.?response/i.test(msg)
  );
}

/**
 * Classify an error as a permanent auth failure (should NOT trigger failover,
 * just inform the user their key is bad).
 */
export function isAuthError(error: unknown): boolean {
  const msg = String(
    (error as any)?.message || (error as any)?.toString?.() || "",
  ).toLowerCase();

  return (
    /api[_ ]?key|permission.?denied|unauthenticated|invalid|401|403|auth/i.test(
      msg,
    ) && !/quota|rate/i.test(msg)
  );
}

/**
 * Check if an error is specific to NVIDIA API (for enhanced error messages).
 */
export function isNvidiaError(error: unknown): boolean {
  const msg = String(
    (error as any)?.message || (error as any)?.toString?.() || "",
  ).toLowerCase();

  return (
    /nvidia|nemotron|integrate\.api\.nvidia\.com/i.test(msg)
  );
}

/**
 * Get a user-friendly error message for NVIDIA API errors.
 */
export function getNvidiaErrorMessage(error: unknown): string {
  const msg = String(
    (error as any)?.message || (error as any)?.toString?.() || "",
  ).toLowerCase();

  if (/401|unauthorized|invalid.*key|authentication/i.test(msg)) {
    return "Invalid NVIDIA API key. Please check your NVIDIA_API_KEY in settings.";
  }
  if (/403|forbidden|permission/i.test(msg)) {
    return "NVIDIA API access denied. Verify your key has access to Nemotron models.";
  }
  if (/429|rate.?limit|quota/i.test(msg)) {
    return "NVIDIA API rate limit exceeded. Please wait and try again.";
  }
  if (/503|unavailable|overloaded/i.test(msg)) {
    return "NVIDIA API temporarily unavailable. Falling back to other providers...";
  }
  if (/timeout|timed out/i.test(msg)) {
    return "NVIDIA API request timed out. The model may be busy.";
  }
  if (/model.*not.*found|invalid.*model/i.test(msg)) {
    return "Nemotron model not available. Please verify the model name.";
  }
  return `NVIDIA API error: ${msg}`;
}
