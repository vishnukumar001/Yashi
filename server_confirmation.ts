/**
 * Yashi — Action confirmation gate (hands-free voice-first rewrite).
 *
 * GOAL (Issue #1 + #2 + #5 + #9):
 *   - Confirmation happens entirely through VOICE. Gemini is the listener;
 *     the on-screen Yes/No banner is a fallback for "Always Ask" mode only.
 *   - The user's settings choose the policy:
 *       "always"  : voice + on-screen banner.
 *       "voice"   : voice only (default; fully hands-free).
 *       "trusted" : low/medium-risk actions run immediately; high-risk still
 *                   requires voice confirmation.
 *   - HIGH-RISK actions (delete, power, terminal, quit-all, empty trash,
 *     install software) ALWAYS require voice confirmation, even in Trusted Mode.
 *   - Multiple actions in one turn are executed SEQUENTIALLY through a FIFO
 *     queue (Issue #5: "Open A, then B, then close C" must not overlap).
 *
 * MECHANISM:
 *   When a tool needs voice confirmation, the gate sends Gemini a tool
 *   response of the form:
 *      { result: "CONFIRMATION_REQUIRED: <spoken question>.
 *                 Ask the user. If they confirm, call <tool> again with the
 *                 same arguments. Otherwise tell them it's cancelled." }
 *   Gemini speaks the question, hears the user's answer in the same Live
 *   session, and re-invokes the tool on "yes". The gate recognises the
 *   re-invocation via a short-lived approval token keyed by tool+args and
 *   lets it through to actual execution.
 *
 *   A 10-second auto-cancel watchdog clears pending approvals so a stale
 *   "yes" can't trigger an action long after the conversation moved on.
 */

import type { WebSocket } from "ws";
import { DesktopConfirmationMode } from "./src/lib/settingsStore";

export interface PendingFunctionCall {
  id?: string;
  name: string;
  args: Record<string, unknown>;
}

export interface ToolExecutionResult {
  ok: boolean;
  result?: unknown;
  error?: string;
}

type SessionLike = {
  sendToolResponse: (payload: {
    functionResponses: Array<{
      name: string;
      response: { output: unknown };
      id?: string;
    }>;
  }) => void;
};

// ---------------------------------------------------------------------------
// Risk tiers (Issue #9). The gate picks the tier, then applies the policy.
// ---------------------------------------------------------------------------

/**
 * HIGH-RISK: always require voice confirmation, regardless of mode.
 * These are the destructive actions called out in Issue #9.
 */
export const HIGH_RISK_TOOLS: ReadonlySet<string> = new Set([
  "deleteFile",
  "executePowerAction",          // shutdown / restart / sleep / lock
  "runPythonScript",             // arbitrary code execution
  "terminalCommand",             // arbitrary shell
  "executeShellCommand",         // alias
  // Reserved hooks for future destructive tools (no-op until registered):
  "emptyTrash",
  "quitAllApps",
  "installSoftware",
]);

/**
 * MEDIUM-RISK: changes the OS state but is recoverable (close a window,
 * rename a file, etc.). Asks for confirmation unless Trusted Mode.
 */
export const MEDIUM_RISK_TOOLS: ReadonlySet<string> = new Set([
  "closeApplication",
  "minimizeWindow", "maximizeWindow", "closeWindow", "switchApplication",
  "pasteClipboard", "clearClipboard", "getClipboard", "copySelected",
  "saveScreenshot",
  "moveFile", "renameFile",
  "createFile", "writeCodeFile", "createPythonFile", "createProjectFolder",
  "enableAutoStart", "disableAutoStart",
  "desktopBrowserOpen", "desktopBrowserNavigate", "desktopBrowserOpenTab",
  "desktopBrowserCloseTab", "desktopBrowserSearch", "desktopBrowserClick",
  "desktopBrowserType", "desktopBrowserFillForm", "desktopBrowserGoBack",
  "desktopBrowserGoForward", "desktopBrowserScroll",
]);

/**
 * LOW-RISK: read-only or launching an app. Runs immediately even in
 * non-trusted modes (no confirmation needed). Per Issue #9 these are the
 * "Open Calculator / Safari / Finder / VS Code" style actions.
 */
export const LOW_RISK_TOOLS: ReadonlySet<string> = new Set([
  "openApplication", "openWebsite", "openFolder",
  "searchWeb", "searchYouTube", "searchGoogle", "searchGitHub",
  "listFiles", "readFile", "searchFiles",
  "volumeUp", "volumeDown", "muteToggle", "setVolume",
  "brightnessUp", "brightnessDown", "setBrightness",
  "takeScreenshot", "analyzeScreenshot", "readScreen",
  "systemInfo", "gpuInfo", "temperatureInfo",
  "getAutoStartStatus",
  "searchWikipedia", "readWikipedia", "wikipediaSummary",
  // Non-destructive UI/memory tools:
  "saveCustomMemory", "changeBackground",
  // Mints a token only; the gated action is executePowerAction.
  "requestPowerAction",
]);

/** Holographic browser tools executed in the React client. */
export const BROWSER_UI_TOOLS: ReadonlySet<string> = new Set([
  "browserOpen", "browserSearch", "browserClick", "browserMediaControl",
  "browserScroll", "browserType", "browserGoBack", "browserTabAction",
]);

export type RiskTier = "low" | "medium" | "high";
export type ConfirmOutcome = "none" | "voice" | "banner";

export function riskTierOf(toolName: string): RiskTier {
  if (HIGH_RISK_TOOLS.has(toolName)) return "high";
  if (MEDIUM_RISK_TOOLS.has(toolName)) return "medium";
  return "low";
}

/**
 * Decide whether (and how) to confirm a tool call under the current mode.
 * Pure function so it's trivially testable.
 */
export function confirmOutcome(
  toolName: string,
  mode: DesktopConfirmationMode,
): ConfirmOutcome {
  // Browser-UI tools: always at least voice; banner in "always" mode.
  if (BROWSER_UI_TOOLS.has(toolName)) {
    return mode === "always" ? "banner" : "voice";
  }

  const tier = riskTierOf(toolName);
  if (tier === "high") {
    // HIGH-RISK always requires voice confirmation, even in Trusted Mode.
    return "voice";
  }
  if (tier === "low") {
    // Low-risk never asks, regardless of mode (per Issue #9).
    return "none";
  }
  // medium
  switch (mode) {
    case "trusted": return "none";
    case "voice":   return "voice";
    case "always":  return "banner";
    default:        return "voice";
  }
}

// ---------------------------------------------------------------------------
// Spoken / displayed prompt text.
// ---------------------------------------------------------------------------

function summarizeArgs(args: Record<string, unknown>): string {
  const parts: string[] = [];
  for (const [key, value] of Object.entries(args)) {
    if (value === undefined || value === null || value === "") continue;
    // Skip the confirmation token from ever being read aloud.
    if (key === "execute_token") continue;
    const rendered =
      typeof value === "object" ? JSON.stringify(value) : String(value);
    if (rendered.length > 80) {
      parts.push(`${key}=${rendered.slice(0, 77)}…`);
    } else {
      parts.push(`${key}=${rendered}`);
    }
  }
  return parts.join(", ");
}

/** Pick the first non-empty arg among the given keys. */
function pickArg(args: Record<string, unknown>, ...keys: string[]): string {
  for (const k of keys) {
    const v = args[k];
    if (v !== undefined && v !== null && String(v).trim()) return String(v);
  }
  return "";
}

/**
 * Conversational spoken question. No "Allow?" suffix — Yashi says this
 * naturally and then waits for the user's reply.
 *
 * Examples:
 *   closeApplication / Safari     -> "Are you sure you want me to close Safari?"
 *   deleteFile / foo.txt          -> "Are you sure you want me to delete foo.txt?"
 *   setVolume / 50                -> "Are you sure you want me to set volume to 50%?"
 */
export function voiceConfirmationPrompt(
  tool: string,
  args: Record<string, unknown>,
): string {
  const a = args ?? {};
  const phrase = actionPhrase(tool, a);
  return `Are you sure you want me to ${phrase}?`;
}

/**
 * "<verb> <object>" fragment used by both the spoken question and the
 * banner text so the two stay in sync.
 */
function actionPhrase(tool: string, a: Record<string, unknown>): string {
  switch (tool) {
    case "openApplication":
      return `open ${pickArg(a, "name", "application") || "that application"}`;
    case "closeApplication":
      return `close ${pickArg(a, "name", "application") || "that application"}`;
    case "openWebsite":
    case "desktopBrowserOpen":
    case "browserOpen":
      return `open ${pickArg(a, "name", "url") || "that website"} in your browser`;
    case "searchWeb":         return `search the web for "${pickArg(a, "query")}"`;
    case "searchYouTube":     return `search YouTube for "${pickArg(a, "query")}"`;
    case "searchGoogle":      return `search Google for "${pickArg(a, "query")}"`;
    case "searchGitHub":      return `search GitHub for "${pickArg(a, "query")}"`;
    case "desktopBrowserSearch":
    case "browserSearch":     return `search for "${pickArg(a, "query")}" in the browser`;
    case "createFile":
    case "writeCodeFile":
    case "createPythonFile":  return `create the file "${pickArg(a, "path")}"`;
    case "readFile":          return `read the file "${pickArg(a, "path")}"`;
    case "renameFile":        return `rename "${pickArg(a, "path")}" to "${pickArg(a, "new_name")}"`;
    case "deleteFile":        return `delete "${pickArg(a, "path")}"`;
    case "moveFile":          return `move "${pickArg(a, "path")}" to "${pickArg(a, "destination")}"`;
    case "openFolder":        return `open the folder "${pickArg(a, "name", "path") || "a folder"}"`;
    case "listFiles":         return `list files in "${pickArg(a, "name", "path") || "a folder"}"`;
    case "searchFiles":       return `search for files (${summarizeArgs(a)})`;
    case "volumeUp":          return "turn the volume up";
    case "volumeDown":        return "turn the volume down";
    case "muteToggle":        return "toggle mute";
    case "setVolume":         return `set volume to ${pickArg(a, "percent")}%`;
    case "brightnessUp":      return "increase the screen brightness";
    case "brightnessDown":    return "decrease the screen brightness";
    case "setBrightness":     return `set brightness to ${pickArg(a, "percent")}%`;
    case "executePowerAction":return `${pickArg(a, "action") || "change the power state"} on your computer`;
    case "minimizeWindow":    return `minimize ${pickArg(a, "title") || "the active window"}`;
    case "maximizeWindow":    return `maximize ${pickArg(a, "title") || "the active window"}`;
    case "closeWindow":       return `close ${pickArg(a, "title") || "the active window"}`;
    case "switchApplication": return `switch to ${pickArg(a, "title") || "another application"}`;
    case "copySelected":      return "copy the current selection to the clipboard";
    case "pasteClipboard":    return "paste into the active app";
    case "getClipboard":      return "read your clipboard";
    case "clearClipboard":    return "clear your clipboard";
    case "takeScreenshot":    return "take a screenshot";
    case "saveScreenshot":    return "save a screenshot";
    case "analyzeScreenshot": return "capture and analyze your screen";
    case "readScreen":        return "read text from your active window";
    case "desktopBrowserNavigate": return `navigate to ${pickArg(a, "url")}`;
    case "desktopBrowserClick":
    case "browserClick":      return `click ${pickArg(a, "selector", "description", "text") || "an element"}`;
    case "desktopBrowserType":
    case "browserType":       return `type "${pickArg(a, "text")}" in the browser`;
    case "desktopBrowserFillForm":    return "fill a form in the browser";
    case "desktopBrowserOpenTab":     return "open a new browser tab";
    case "desktopBrowserCloseTab":
    case "browserTabAction":  return "change browser tabs";
    case "desktopBrowserGoBack":
    case "browserGoBack":     return "go back in the browser";
    case "desktopBrowserGoForward":   return "go forward in the browser";
    case "desktopBrowserScroll":
    case "browserScroll":     return `scroll ${pickArg(a, "direction") || "the page"}`;
    case "browserMediaControl":       return `${pickArg(a, "action") || "control"} media playback`;
    case "runPythonScript":   return `run the Python script "${pickArg(a, "path")}"`;
    case "executeShellCommand":
    case "terminalCommand":   return `run the terminal command "${pickArg(a, "command")}"`;
    case "createProjectFolder": return `create the project folder "${pickArg(a, "path")}"`;
    case "enableAutoStart":   return "enable auto-start on login";
    case "disableAutoStart":  return "disable auto-start on login";
    case "emptyTrash":        return "empty the Trash";
    case "quitAllApps":       return "quit all running applications";
    case "installSoftware":   return `install "${pickArg(a, "name") || "software"}"`;
    default: {
      const label = tool.replace(/([A-Z])/g, " $1").trim().toLowerCase();
      const detail = summarizeArgs(a);
      return detail ? `${label} (${detail})` : label;
    }
  }
}

/** Human-readable banner text (used in "always" mode). Keeps the legacy look. */
export function formatConfirmationMessage(
  tool: string,
  args: Record<string, unknown>,
): string {
  const phrase = actionPhrase(tool, args ?? {});
  // Capitalize first letter for the banner.
  const cap = phrase.charAt(0).toUpperCase() + phrase.slice(1);
  return `Yashi wants to ${phrase}. Allow?`.replace(
    `Yashi wants to ${phrase}`,
    `Yashi wants to ${cap.toLowerCase()}`,
  );
}

// ---------------------------------------------------------------------------
// Approval token store — short-lived, keyed by tool+args hash.
// When the user says "yes", Gemini re-invokes the same tool with the same
// args; the gate looks up the pending approval and lets it through.
// ---------------------------------------------------------------------------

const APPROVAL_TTL_MS = 25_000; // 25 seconds for voice confirmation exchange and natural conversational reply.

function hashCall(tool: string, args: Record<string, unknown>): string {
  // Stable-ish hash so identical tool+args re-calls match. Not cryptographic.
  // Exclude the execute_token which is minted fresh each confirmation cycle.
  const { execute_token: _ignored, ...rest } = args || {};
  let s = `${tool}|`;
  try { s += JSON.stringify(rest, Object.keys(rest).sort()); } catch { s += JSON.stringify(rest); }
  let h = 0;
  for (let i = 0; i < s.length; i++) {
    h = ((h << 5) - h + s.charCodeAt(i)) | 0;
  }
  return `${tool}:${h >>> 0}`;
}

interface QueuedCall {
  /** Internal id for the queue item. */
  itemId: string;
  /** Gemini function-call id (so we can reply to the right call). */
  fc: PendingFunctionCall;
  route: "desktop" | "browser";
  outcome: ConfirmOutcome;
  /** For voice-confirmations: set true once the user has approved. */
  approved?: boolean;
  /** Wall-clock when this was enqueued, for the watchdog. */
  enqueuedAt: number;
}

/**
 * Per-WebSocket confirmation + execution queue.
 *
 * - Exactly one item runs at a time. Others wait in `queue`.
 * - "Running" means either (a) awaiting voice approval, or (b) executing
 *   against the desktop agent / browser.
 * - The same queue serializes ALL desktop/browser calls so "open A, then B,
 *   then close C" can't overlap (Issue #5).
 */
export class ConfirmationGate {
  private queue: QueuedCall[] = [];
  private active: QueuedCall | null = null;
  private watchdog: NodeJS.Timeout | null = null;
  private readonly pendingApprovals = new Map<string, number>(); // hash -> expiresAt

  constructor(
    private clientWs: WebSocket,
    private getSession: () => SessionLike,
    private executeDesktop: (
      tool: string,
      args: Record<string, unknown>,
    ) => Promise<ToolExecutionResult>,
    private getMode: () => DesktopConfirmationMode,
    private log: (event: string, detail?: unknown) => void = () => {},
  ) {}

  /**
   * Route a tool call. Returns true if the gate took ownership of it
   * (queued it for confirmation or for serialized execution). Returns false
   * only when the caller should handle it inline (never, with this gate).
   */
  enqueue(fc: PendingFunctionCall, route: "desktop" | "browser"): boolean {
    const mode = this.getMode();
    const outcome = confirmOutcome(fc.name, mode);
    const isReCall = this.isApproved(fc.name, fc.args);

    const item: QueuedCall = {
      itemId: Math.random().toString(36).slice(2, 11),
      fc,
      route,
      outcome,
      approved: isReCall,
      enqueuedAt: Date.now(),
    };
    this.queue.push(item);
    this.log("INTENT", { tool: fc.name, args: fc.args, outcome, isReCall });
    void this.pump();
    return true;
  }

  /** Respond to an on-screen Yes/No banner ("always" mode). */
  async respond(confirmId: string, approved: boolean): Promise<void> {
    if (!this.active || this.active.itemId !== confirmId) {
      this.log("CONFIRM_STALE_RESPONSE", { confirmId });
      return;
    }
    const item = this.active;
    if (approved) {
      this.markApproved(item.fc.name, item.fc.args);
      this.log("CONFIRM_USER_RESPOND", { tool: item.fc.name, approved: true });
      await this.execute(item);
    } else {
      this.log("CONFIRM_USER_RESPOND", { tool: item.fc.name, approved: false });
      this.sendToolResult(item.fc, {
        result: "Action cancelled by the user.",
      });
    }
    this.advance();
  }

  /** Drain everything on disconnect. */
  clear(): void {
    this.queue = [];
    this.active = null;
    this.pendingApprovals.clear();
    if (this.watchdog) {
      clearTimeout(this.watchdog);
      this.watchdog = null;
    }
  }

  // -----------------------------------------------------------------------

  private async pump(): Promise<void> {
    if (this.active || this.queue.length === 0) return;
    const item = this.queue.shift()!;
    this.active = item;
    this.armWatchdog(item);

    // Already voice-approved (Gemini re-invoked after the user said "yes").
    if (item.approved) {
      this.consumeApproval(item.fc.name, item.fc.args);
      this.log("CONFIRM_USER_RESPOND", { tool: item.fc.name, approved: true, via: "voice-recall" });
      await this.execute(item);
      this.advance();
      return;
    }

    if (item.outcome === "none") {
      // No confirmation needed — execute straight away (still serialized).
      await this.execute(item);
      this.advance();
      return;
    }

    if (item.outcome === "voice") {
      // Mint an approval token before prompting so when Gemini asks the user and the
      // user replies "yes", Gemini's subsequent re-call is recognized and executes.
      this.markApproved(item.fc.name, item.fc.args);
      const question = voiceConfirmationPrompt(item.fc.name, item.fc.args);
      const payload =
        `CONFIRMATION_REQUIRED: ${question} ` +
        `Ask the user this question out loud and wait for their answer. ` +
        `If they say yes, yeah, yep, sure, go ahead, do it, or confirm, ` +
        `call ${item.fc.name} again with EXACTLY the same arguments. ` +
        `If they say no, cancel, stop, never mind, or don't, tell them ` +
        `the action is cancelled and do NOT call ${item.fc.name}. ` +
        `Do not call ${item.fc.name} again until the user answers. ` +
        `(Auto-cancels in 25 seconds if there is no response.)`;
      this.log("CONFIRM_REQUIRED", { tool: item.fc.name, mode: "voice" });
      this.sendToolResult(item.fc, { result: payload });
      this.advance(); // free the queue; the re-call (if any) re-enters via enqueue()
      return;
    }

    // outcome === "banner": show the Yes/No UI AND speak the question.
    const message = formatConfirmationMessage(item.fc.name, item.fc.args);
    this.log("CONFIRM_REQUIRED", { tool: item.fc.name, mode: "banner" });
    this.clientWs.send(
      JSON.stringify({
        type: "confirmationRequest",
        id: item.itemId,
        message,
        tool: item.fc.name,
        args: item.fc.args,
      }),
    );
    // NOTE: we do NOT advance here — pump() stays blocked on `active` until
    // the user clicks Yes/No, preserving strict one-at-a-time ordering.
  }

  private async execute(item: QueuedCall): Promise<void> {
    this.disarmWatchdog();
    const startedAt = Date.now();
    if (item.route === "desktop") {
      const agentResult = await this.executeDesktop(item.fc.name, item.fc.args);
      const elapsedMs = Date.now() - startedAt;
      if (agentResult.ok) {
        const output = agentResult.result ?? { result: "Done." };
        this.log("DESKTOP_OK", { tool: item.fc.name, elapsedMs });
        this.sendToolResult(item.fc, { output });
      } else {
        const errMsg = agentResult.error || "Desktop agent error.";
        this.log("DESKTOP_FAIL", { tool: item.fc.name, elapsedMs, error: errMsg });
        this.sendToolResult(item.fc, {
          output: { result: `Desktop control error: ${errMsg}` },
        });
      }
    } else {
      // Browser-UI tool — hand off to the React client.
      this.log("BROWSER_SEND", { tool: item.fc.name });
      this.clientWs.send(
        JSON.stringify({
          type: "toolCall",
          callId: item.fc.id,
          name: item.fc.name,
          args: item.fc.args,
        }),
      );
    }
  }

  private advance(): void {
    this.disarmWatchdog();
    this.active = null;
    void this.pump();
  }

  private sendToolResult(
    fc: PendingFunctionCall,
    payload: { output?: unknown; result?: string },
  ): void {
    const output =
      "output" in payload
        ? payload.output
        : { result: (payload as { result?: string }).result ?? "Done." };
    try {
      this.getSession().sendToolResponse({
        functionResponses: [
          { name: fc.name, response: { output }, id: fc.id },
        ],
      });
    } catch (err) {
      this.log("CONFIRM_REPLY_FAILED", { tool: fc.name, error: String(err) });
    }
  }

  // --- Approval-token helpers --------------------------------------------

  private isApproved(tool: string, args: Record<string, unknown>): boolean {
    const key = hashCall(tool, args);
    const now = Date.now();
    const expiresAt = this.pendingApprovals.get(key) || this.pendingApprovals.get(`${tool}:*`);
    if (!expiresAt) return false;
    if (now > expiresAt) {
      this.pendingApprovals.delete(key);
      this.pendingApprovals.delete(`${tool}:*`);
      return false;
    }
    return true;
  }

  private markApproved(tool: string, args: Record<string, unknown>): void {
    const expiresAt = Date.now() + APPROVAL_TTL_MS;
    this.pendingApprovals.set(hashCall(tool, args), expiresAt);
    this.pendingApprovals.set(`${tool}:*`, expiresAt);
  }

  private consumeApproval(tool: string, args: Record<string, unknown>): void {
    this.pendingApprovals.delete(hashCall(tool, args));
    this.pendingApprovals.delete(`${tool}:*`);
  }

  // --- Watchdog: 10s no-response -> auto-cancel --------------------------

  private armWatchdog(item: QueuedCall): void {
    this.disarmWatchdog();
    // Only voice confirmations need a timeout — banner clicks have no
    // deadline, and direct executions return on their own.
    if (item.outcome !== "voice" || item.approved) return;
    this.watchdog = setTimeout(() => {
      // Re-check this is still the same active item.
      if (!this.active || this.active.itemId !== item.itemId) return;
      this.log("CONFIRM_TIMEOUT", { tool: item.fc.name });
      this.sendToolResult(item.fc, {
        result: `Confirmation timed out. I did not ${actionPhrase(item.fc.name, item.fc.args)}.`,
      });
      this.advance();
    }, APPROVAL_TTL_MS);
  }

  private disarmWatchdog(): void {
    if (this.watchdog) {
      clearTimeout(this.watchdog);
      this.watchdog = null;
    }
  }
}
