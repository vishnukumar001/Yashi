/**
 * ApiKeyGate — first-run onboarding.
 *
 * Guides the user through initial setup:
 *   1. Enter their name.
 *   2. Enter their Google Gemini API key.
 *   3. Validates the key via live API call and saves configuration
 *      encrypted and local to the user's machine.
 *   4. Seamlessly launches into Yashi.
 *
 * The API key is NEVER committed, never hardcoded, and never exposed.
 */

import { useEffect, useState, type ReactNode, type FormEvent } from "react";
import {
  KeyRound,
  Loader2,
  ExternalLink,
  ShieldCheck,
  User,
  ArrowRight,
  ArrowLeft,
  CheckCircle2,
  Sparkles,
} from "lucide-react";
import { saveSettings } from "../lib/settingsStore";

type Phase = "checking" | "setup" | "ready";
type SetupStep = "name" | "apikey" | "done";

export function ApiKeyGate({ children }: { children: ReactNode }) {
  const [phase, setPhase] = useState<Phase>("checking");
  const [step, setStep] = useState<SetupStep>("name");
  const [userName, setUserName] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch("/api/config", { cache: "no-store" });
        const data = await res.json();
        if (cancelled) return;

        if (data.hasApiKey && data.userName) {
          setPhase("ready");
        } else {
          if (data.userName) {
            setUserName(data.userName);
            setStep("apikey");
          } else {
            setStep("name");
          }
          setPhase("setup");
        }
      } catch {
        // Backend not up yet — prompt setup rather than hard fail
        if (!cancelled) {
          setStep("name");
          setPhase("setup");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  function handleNameNext(e: FormEvent) {
    e.preventDefault();
    const trimmed = userName.trim();
    if (!trimmed) {
      setError("Please enter your name to continue.");
      return;
    }
    setError(null);
    setStep("apikey");
  }

  async function handleKeySubmit(e: FormEvent) {
    e.preventDefault();
    const trimmedKey = apiKey.trim();
    const trimmedName = userName.trim() || "User";
    if (!trimmedKey || submitting) return;

    setSubmitting(true);
    setError(null);

    try {
      const res = await fetch("/api/config/apikey", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ apiKey: trimmedKey, userName: trimmedName }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Could not verify or save the key.");

      // Mirror user name to browser settings store
      saveSettings({ userName: trimmedName });

      setStep("done");
      setTimeout(() => {
        setApiKey("");
        setPhase("ready");
      }, 1000);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong.");
    } finally {
      setSubmitting(false);
    }
  }

  if (phase === "ready") return <>{children}</>;

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-[#050509] text-white">
      {/* Ambient glows */}
      <div className="pointer-events-none absolute -left-40 -top-40 h-[460px] w-[460px] rounded-full bg-indigo-700/20 blur-[140px]" />
      <div className="pointer-events-none absolute -bottom-40 -right-40 h-[500px] w-[500px] rounded-full bg-cyan-700/15 blur-[160px]" />

      {phase === "checking" ? (
        <div className="flex flex-col items-center gap-4 text-white/60">
          <Loader2 className="h-8 w-8 animate-spin text-cyan-400" />
          <span className="text-sm font-mono tracking-wide">Initializing Yashi…</span>
        </div>
      ) : (
        <div className="relative z-10 w-[min(92vw,480px)] rounded-3xl border border-white/10 bg-white/[0.04] p-8 shadow-[0_30px_90px_rgba(0,0,0,0.7)] backdrop-blur-2xl">
          {/* Progress Indicators */}
          <div className="mb-6 flex items-center justify-center gap-2">
            <div
              className={`h-1.5 w-12 rounded-full transition-all duration-300 ${
                step === "name"
                  ? "bg-gradient-to-r from-indigo-500 to-cyan-500"
                  : "bg-cyan-500/60"
              }`}
            />
            <div
              className={`h-1.5 w-12 rounded-full transition-all duration-300 ${
                step === "apikey"
                  ? "bg-gradient-to-r from-indigo-500 to-cyan-500"
                  : step === "done"
                  ? "bg-cyan-500/60"
                  : "bg-white/10"
              }`}
            />
          </div>

          {/* STEP 1: Name Input */}
          {step === "name" && (
            <form onSubmit={handleNameNext}>
              <div className="mb-6 flex flex-col items-center text-center">
                <div className="mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-gradient-to-br from-indigo-500/30 to-cyan-500/20 ring-1 ring-white/10">
                  <User className="h-6 w-6 text-indigo-300" />
                </div>
                <h1 className="text-xl font-semibold tracking-tight text-white">
                  Welcome to Yashi
                </h1>
                <p className="mt-2 text-xs leading-relaxed text-white/60">
                  Your autonomous desktop companion and cybersecurity co-pilot.
                  First, what should Yashi call you?
                </p>
              </div>

              <label className="mb-1.5 block text-xs font-medium uppercase tracking-wider text-white/40">
                Your Name or Callsign
              </label>
              <input
                type="text"
                autoFocus
                value={userName}
                onChange={(e) => setUserName(e.target.value)}
                placeholder="e.g. Rudra, Alex, Cipher"
                spellCheck={false}
                className="w-full rounded-xl border border-white/10 bg-black/40 px-4 py-3 text-sm text-white placeholder-white/20 outline-none transition focus:border-cyan-400/60 focus:ring-2 focus:ring-cyan-500/20"
              />

              {error && (
                <p className="mt-3 rounded-lg bg-red-500/10 px-3 py-2 text-xs text-red-300 ring-1 ring-red-500/20">
                  {error}
                </p>
              )}

              <button
                type="submit"
                disabled={!userName.trim()}
                className="mt-6 flex w-full items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-indigo-500 to-cyan-500 px-4 py-3 text-sm font-semibold text-white transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-40 cursor-pointer"
              >
                <span>Continue to API Key</span>
                <ArrowRight className="h-4 w-4" />
              </button>
            </form>
          )}

          {/* STEP 2: API Key Input */}
          {step === "apikey" && (
            <form onSubmit={handleKeySubmit}>
              <div className="mb-6 flex flex-col items-center text-center">
                <div className="mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-gradient-to-br from-indigo-500/30 to-cyan-500/20 ring-1 ring-white/10">
                  <KeyRound className="h-6 w-6 text-cyan-300" />
                </div>
                <h1 className="text-xl font-semibold tracking-tight text-white">
                  Enter Gemini API Key
                </h1>
                <p className="mt-2 text-xs leading-relaxed text-white/60">
                  Yashi runs on Google Gemini Live for real-time duplex voice and
                  system automation. Paste your Gemini key below to get started.
                </p>
              </div>

              <label className="mb-1.5 block text-xs font-medium uppercase tracking-wider text-white/40">
                Google Gemini API Key
              </label>
              <input
                type="password"
                autoFocus
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                placeholder="AIzaSy…"
                spellCheck={false}
                className="w-full rounded-xl border border-white/10 bg-black/40 px-4 py-3 text-sm text-white placeholder-white/20 outline-none transition focus:border-cyan-400/60 focus:ring-2 focus:ring-cyan-500/20 font-mono"
              />

              {error && (
                <p className="mt-3 rounded-lg bg-red-500/10 px-3 py-2 text-xs text-red-300 ring-1 ring-red-500/20">
                  {error}
                </p>
              )}

              <div className="mt-6 flex items-center gap-3">
                <button
                  type="button"
                  onClick={() => {
                    setError(null);
                    setStep("name");
                  }}
                  disabled={submitting}
                  className="flex items-center justify-center gap-1.5 rounded-xl border border-white/10 bg-white/5 px-4 py-3 text-sm font-medium text-white/70 transition hover:bg-white/10 hover:text-white disabled:opacity-40 cursor-pointer"
                >
                  <ArrowLeft className="h-4 w-4" />
                  <span>Back</span>
                </button>

                <button
                  type="submit"
                  disabled={submitting || !apiKey.trim()}
                  className="flex flex-1 items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-indigo-500 to-cyan-500 px-4 py-3 text-sm font-semibold text-white transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-40 cursor-pointer"
                >
                  {submitting ? (
                    <>
                      <Loader2 className="h-4 w-4 animate-spin" />
                      <span>Validating Key…</span>
                    </>
                  ) : (
                    <>
                      <Sparkles className="h-4 w-4" />
                      <span>Launch Yashi</span>
                    </>
                  )}
                </button>
              </div>

              <div className="mt-5 flex items-center justify-between text-xs text-white/40">
                <span className="inline-flex items-center gap-1.5">
                  <ShieldCheck className="h-3.5 w-3.5 text-emerald-400" />
                  <span>Encrypted locally (AES-256-GCM)</span>
                </span>
                <a
                  href="https://aistudio.google.com/app/apikey"
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-1 text-cyan-300 transition hover:text-cyan-200 underline underline-offset-2"
                >
                  <span>Get a free key</span>
                  <ExternalLink className="h-3 w-3" />
                </a>
              </div>
            </form>
          )}

          {/* STEP 3: Setup Complete confirmation */}
          {step === "done" && (
            <div className="flex flex-col items-center py-6 text-center">
              <div className="mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-emerald-500/20 ring-1 ring-emerald-500/30 text-emerald-400">
                <CheckCircle2 className="h-8 w-8" />
              </div>
              <h2 className="text-xl font-semibold text-white">
                All Set, {userName || "there"}!
              </h2>
              <p className="mt-2 text-xs text-white/60">
                Configuration verified and encrypted. Welcome to Yashi.
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
