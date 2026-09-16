/**
 * Yashi Settings Store — persistent user preferences (V2).
 *
 * Establishes the persistence pattern for Yashi: settings are mirrored to
 * localStorage (instant local read) AND synced to the backend (settings.json)
 * so auto-start / wake-word preferences survive across browsers and the
 * Python desktop agent can read them too.
 *
 * Pattern follows the existing codebase conventions: plain state + ref mirrors.
 * No Context/Zustand — this is deliberately lightweight to match audio.ts/memoryTypes.ts.
 */

/**
 * How Yashi confirms desktop actions before running them.
 * - "always"  : Yashi asks by voice AND shows the on-screen Yes/No banner.
 * - "voice"   : Hands-free. Yashi asks by voice only; no banner. (Default.)
 * - "trusted" : Low/medium-risk actions run immediately without asking.
 *               High-risk actions (delete, power, terminal, etc.) still
 *               require voice confirmation.
 */
export type DesktopConfirmationMode = "always" | "voice" | "trusted";

export interface YashiSettings {
  /** Launch Yashi (backends + browser tab) silently on login. */
  autoStart: boolean;
  /** Enable the always-listening wake-word detector. */
  wakeWordEnabled: boolean;
  /** Phrase that activates Yashi (case-insensitive substring match). */
  wakePhrase: string;
  /** Preferred microphone device id ("" = system default). */
  micDeviceId: string;
  /** Wake-word sensitivity: 0 (strict) .. 100 (loose). Affects debounce window. */
  sensitivity: number;
  /** Master toggle for UI animations. */
  animations: boolean;
  /** Name of the preferred Gemini voice. */
  voiceName: string;
  /** Voice gender lock - "female" to enforce female voice only */
  voiceGender: "female" | "auto";
  /** User's preferred name or nickname for personalized conversations. */
  userName: string;
  /** When/how Yashi asks for confirmation before desktop actions. */
  desktopConfirmation: DesktopConfirmationMode;
}

export const DEFAULT_SETTINGS: YashiSettings = {
  userName: "",
  autoStart: false,
  wakeWordEnabled: false,
  wakePhrase: "hey yashi",
  micDeviceId: "",
  sensitivity: 60,
  animations: true,
  voiceName: "Aoede",
  voiceGender: "female",
  // Hands-free by default — matches the product goal of a real voice assistant.
  desktopConfirmation: "voice",
};

const STORAGE_KEY = "yashi.settings.v2";
const LEGACY_STORAGE_KEY = "vexa.settings.v2";

/** Settings keys that the browser should never persist (security). */
const NEVER_PERSIST: ReadonlySet<keyof YashiSettings> = new Set([]);

/**
 * Load settings from localStorage, merged over defaults so new keys always
 * have a sane value even when an older payload is present.
 */
export function loadSettings(): YashiSettings {
  if (typeof window === "undefined") return { ...DEFAULT_SETTINGS };
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY) || window.localStorage.getItem(LEGACY_STORAGE_KEY);
    if (!raw) return { ...DEFAULT_SETTINGS };
    const parsed = JSON.parse(raw) as Partial<YashiSettings>;
    return { ...DEFAULT_SETTINGS, ...parsed };
  } catch {
    return { ...DEFAULT_SETTINGS };
  }
}

/**
 * Persist a full or partial settings update to localStorage.
 * Returns the fully merged settings object.
 */
export function saveSettings(patch: Partial<YashiSettings>): YashiSettings {
  const current = loadSettings();
  const next: YashiSettings = { ...current, ...patch };
  if (typeof window !== "undefined") {
    try {
      // Strip any sensitive keys before writing to localStorage.
      const safe: Record<string, unknown> = {};
      (Object.keys(next) as (keyof YashiSettings)[]).forEach((k) => {
        if (!NEVER_PERSIST.has(k)) safe[k] = next[k];
      });
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify(safe));
    } catch {
      /* localStorage may be unavailable (private mode) — fail silently. */
    }
  }
  // Best-effort sync to backend so the Python agent can read auto-start state.
  void syncSettingsToBackend(next).catch(() => {});
  return next;
}

/** Push settings to the backend (server.ts persists to settings.json). */
async function syncSettingsToBackend(settings: YashiSettings): Promise<void> {
  try {
    await fetch("/api/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(settings),
    });
  } catch {
    /* Backend may be briefly unavailable during boot — non-fatal. */
  }
}

