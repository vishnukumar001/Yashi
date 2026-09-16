/**
 * Yashi Session Mode Manager — Sleep & Lock Mode (Features 2 & 3).
 *
 * Manages the assistant's operational state:
 *   - active:   Normal operation — listening, speaking, executing commands.
 *   - sleeping:  Mic disabled, screen share paused, avatar idle, wake word listens.
 *   - locked:    All commands ignored, requires wake phrase to unlock.
 *
 * The manager is a singleton so both App.tsx and the wake-word detector can
 * coordinate mode transitions without prop-drilling.
 *
 * Usage:
 *   import { sessionModeManager, SessionMode } from "./lib/sessionMode";
 *   sessionModeManager.onModeChange = (mode) => { ... };
 *   sessionModeManager.enterSleep();
 *   sessionModeManager.enterLock();
 *   sessionModeManager.wake();
 */

export type SessionMode = "active" | "sleeping" | "locked";

type ModeChangeCallback = (mode: SessionMode) => void;

class SessionModeManager {
  private _mode: SessionMode = "active";
  private _onModeChange: ModeChangeCallback | null = null;

  /** The current session mode. */
  get mode(): SessionMode {
    return this._mode;
  }

  /**
   * Register a callback fired whenever the mode changes.
   * Overwrites any previous listener (single-listener pattern, matching audio.ts).
   */
  set onModeChange(fn: ModeChangeCallback | null) {
    this._onModeChange = fn;
  }

  /** Enter sleep mode — mic off, screen share paused, avatar idle. */
  enterSleep(): void {
    if (this._mode === "sleeping") return; // idempotent
    this._mode = "sleeping";
    this._notify();
  }

  /** Enter lock mode — all commands ignored, wake phrase required. */
  enterLock(): void {
    if (this._mode === "locked") return; // idempotent
    this._mode = "locked";
    this._notify();
  }

  /** Wake from sleep or lock — resume active mode. */
  wake(): void {
    if (this._mode === "active") return; // idempotent
    this._mode = "active";
    this._notify();
  }

  /** Whether commands should be processed. */
  get isActive(): boolean {
    return this._mode === "active";
  }

  /** Whether the assistant is in any suspended state (sleep or lock). */
  get isSuspended(): boolean {
    return this._mode !== "active";
  }

  /** Reset to active mode (e.g., on new session). */
  reset(): void {
    this._mode = "active";
    this._notify();
  }

  private _notify(): void {
    try {
      this._onModeChange?.(this._mode);
    } catch {
      /* listener errors must never break the mode manager */
    }
  }
}

/** Singleton instance — import wherever needed. */
export const sessionModeManager = new SessionModeManager();
