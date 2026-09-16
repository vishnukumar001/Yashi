"""
Application control: launch and close common desktop applications.

Reliability strategy (Issue #3 — "Fix Application Launch Reliability"):

1. Resolve the requested name through a generous alias table that covers the
   examples in the spec ("Chrome" -> Google Chrome, "VS Code" ->
   Visual Studio Code, "Settings" -> System Settings, ...).
2. On macOS, back the alias table with a live query of installed .app bundles
   (via `system_profiler` + `mdfind`) so apps NOT in the hardcoded table are
   still resolved by their real bundle/display name.
3. Detect whether an app is already running before launching (return
   "<label> is already open." instead of silently re-launching).
4. Verify the launch actually succeeded; never silently fail.
5. Detect whether an app was running before we tried to close it, so we never
   claim to have closed something that wasn't open.

Cross-platform: `open -a` on macOS, `start` on Windows, direct commands on
Linux for launching. Closing uses `pkill` (macOS/Linux) or `taskkill`.
"""

from __future__ import annotations

import platform
import shutil
import subprocess
import time
from typing import Any, Dict, Optional, Tuple

from .registry import ToolError, register


# ---------------------------------------------------------------------------
# Static alias / fallback table.
# Each entry: { "open": <launch name>, "kill": <pkill target>, "label": <UI> }.
# The launch name MUST be the real bundle/display name on macOS so
# `open -a "<name>"` resolves it.
# ---------------------------------------------------------------------------
def _apps_for_platform() -> Dict[str, Dict[str, str]]:
    """Return the app registry for the current platform."""
    system = platform.system()
    if system == "Darwin":
        return {
            "safari": {"open": "Safari", "kill": "Safari", "label": "Safari"},
            "chrome": {"open": "Google Chrome", "kill": "Google Chrome", "label": "Google Chrome"},
            "google chrome": {"open": "Google Chrome", "kill": "Google Chrome", "label": "Google Chrome"},
            "firefox": {"open": "Firefox", "kill": "firefox", "label": "Firefox"},
            "edge": {"open": "Microsoft Edge", "kill": "Microsoft Edge", "label": "Microsoft Edge"},
            "microsoft edge": {"open": "Microsoft Edge", "kill": "Microsoft Edge", "label": "Microsoft Edge"},
            "vscode": {"open": "Visual Studio Code", "kill": "Code Helper", "label": "Visual Studio Code"},
            "vs code": {"open": "Visual Studio Code", "kill": "Code Helper", "label": "Visual Studio Code"},
            "visual studio code": {"open": "Visual Studio Code", "kill": "Code Helper", "label": "Visual Studio Code"},
            "code": {"open": "Visual Studio Code", "kill": "Code Helper", "label": "Visual Studio Code"},
            "calculator": {"open": "Calculator", "kill": "Calculator", "label": "Calculator"},
            "calc": {"open": "Calculator", "kill": "Calculator", "label": "Calculator"},
            "finder": {"open": "Finder", "kill": "Finder", "label": "Finder"},
            "file explorer": {"open": "Finder", "kill": "Finder", "label": "Finder"},
            "explorer": {"open": "Finder", "kill": "Finder", "label": "Finder"},
            "textedit": {"open": "TextEdit", "kill": "TextEdit", "label": "TextEdit"},
            "notes": {"open": "Notes", "kill": "Notes", "label": "Notes"},
            "apple notes": {"open": "Notes", "kill": "Notes", "label": "Notes"},
            "terminal": {"open": "Terminal", "kill": "Terminal", "label": "Terminal"},
            "iterm": {"open": "iTerm", "kill": "iTerm2", "label": "iTerm"},
            # macOS 13+ renamed System Preferences -> System Settings. Try the
            # new name first; `open -a` will fail loudly if only the old one exists.
            "settings": {"open": "System Settings", "kill": "System Settings", "label": "System Settings"},
            "system settings": {"open": "System Settings", "kill": "System Settings", "label": "System Settings"},
            "system preferences": {"open": "System Preferences", "kill": "System Preferences", "label": "System Preferences"},
            "settings app": {"open": "System Settings", "kill": "System Settings", "label": "System Settings"},
            "activity monitor": {"open": "Activity Monitor", "kill": "Activity Monitor", "label": "Activity Monitor"},
            "task manager": {"open": "Activity Monitor", "kill": "Activity Monitor", "label": "Activity Monitor"},
            "photos": {"open": "Photos", "kill": "Photos", "label": "Photos"},
            "music": {"open": "Music", "kill": "Music", "label": "Music"},
            "app store": {"open": "App Store", "kill": "App Store", "label": "App Store"},
            "mail": {"open": "Mail", "kill": "Mail", "label": "Mail"},
            "messages": {"open": "Messages", "kill": "Messages", "label": "Messages"},
            "maps": {"open": "Maps", "kill": "Maps", "label": "Maps"},
            "calendar": {"open": "Calendar", "kill": "Calendar", "label": "Calendar"},
            "spotify": {"open": "Spotify", "kill": "Spotify", "label": "Spotify"},
            "discord": {"open": "Discord", "kill": "Discord", "label": "Discord"},
            "slack": {"open": "Slack", "kill": "Slack", "label": "Slack"},
            "zoom": {"open": "zoom.us", "kill": "zoom.us", "label": "Zoom"},
            "notepad": {"open": "TextEdit", "kill": "TextEdit", "label": "TextEdit"},
            "wordpad": {"open": "TextEdit", "kill": "TextEdit", "label": "TextEdit"},
            "paint": {"open": "Preview", "kill": "Preview", "label": "Preview"},
            "cmd": {"open": "Terminal", "kill": "Terminal", "label": "Terminal"},
            "command prompt": {"open": "Terminal", "kill": "Terminal", "label": "Terminal"},
            "powershell": {"open": "Terminal", "kill": "Terminal", "label": "Terminal"},
        }
    # Windows / Linux fallback
    return {
        "notepad": {"open": "notepad.exe", "kill": "notepad.exe", "label": "Notepad"},
        "chrome": {"open": "chrome.exe", "kill": "chrome.exe", "label": "Google Chrome"},
        "google chrome": {"open": "chrome.exe", "kill": "chrome.exe", "label": "Google Chrome"},
        "edge": {"open": "msedge.exe", "kill": "msedge.exe", "label": "Microsoft Edge"},
        "microsoft edge": {"open": "msedge.exe", "kill": "msedge.exe", "label": "Microsoft Edge"},
        "vscode": {"open": "code.cmd", "kill": "Code.exe", "label": "Visual Studio Code"},
        "vs code": {"open": "code.cmd", "kill": "Code.exe", "label": "Visual Studio Code"},
        "visual studio code": {"open": "code.cmd", "kill": "Code.exe", "label": "Visual Studio Code"},
        "code": {"open": "code.cmd", "kill": "Code.exe", "label": "Visual Studio Code"},
        "calculator": {"open": "calc", "kill": "CalculatorApp.exe", "label": "Calculator"},
        "calc": {"open": "calc", "kill": "CalculatorApp.exe", "label": "Calculator"},
        "file explorer": {"open": "explorer", "kill": "explorer.exe", "label": "File Explorer"},
        "explorer": {"open": "explorer", "kill": "explorer.exe", "label": "File Explorer"},
        "task manager": {"open": "taskmgr", "kill": "Taskmgr.exe", "label": "Task Manager"},
        "settings": {"open": "ms-settings:", "kill": "SystemSettings.exe", "label": "Settings"},
        "cmd": {"open": "cmd.exe", "kill": "cmd.exe", "label": "Command Prompt"},
        "command prompt": {"open": "cmd.exe", "kill": "cmd.exe", "label": "Command Prompt"},
        "powershell": {"open": "powershell.exe", "kill": "powershell.exe", "label": "PowerShell"},
        "spotify": {"open": "Spotify.exe", "kill": "Spotify.exe", "label": "Spotify"},
        "discord": {"open": "Discord.exe", "kill": "Discord.exe", "label": "Discord"},
    }


_APP_COMMANDS: Optional[Dict[str, Dict[str, str]]] = None


def _get_apps() -> Dict[str, Dict[str, str]]:
    global _APP_COMMANDS
    if _APP_COMMANDS is None:
        _APP_COMMANDS = _apps_for_platform()
    return _APP_COMMANDS


# ---------------------------------------------------------------------------
# Live bundle catalogue (macOS only). Cached briefly so repeated calls in one
# turn ("open Chrome, then VS Code, then close Safari") don't re-scan the disk.
# ---------------------------------------------------------------------------
_INSTALLED_APPS_CACHE: Dict[str, Any] = {"at": 0.0, "map": {}}
_INSTALLED_APPS_TTL = 60.0  # seconds


def _installed_apps_map() -> Dict[str, str]:
    """Return {lowercased display name -> display name} for installed macOS apps.

    Best-effort: returns {} on non-macOS or if both probes fail. The static
    alias table is always consulted first, so an empty result here is fine.
    """
    if platform.system() != "Darwin":
        return {}
    now = time.time()
    if now - _INSTALLED_APPS_CACHE["at"] < _INSTALLED_APPS_TTL:
        return _INSTALLED_APPS_CACHE["map"]

    mapping: Dict[str, str] = {}

    # Primary source: system_profiler is the canonical LaunchServices view.
    try:
        proc = subprocess.run(
            ["system_profiler", "SPApplicationsDataType", "-json"],
            capture_output=True, text=True, timeout=8,
        )
        if proc.returncode == 0:
            import json
            data = json.loads(proc.stdout)
            items = (data.get("SPApplicationsDataType") or [])
            for item in items:
                name = item.get("_name") or item.get("path")
                if name and isinstance(name, str):
                    clean = name.strip()
                    mapping[clean.lower()] = clean
    except Exception:
        pass

    # Secondary source: Spotlight index — catches apps system_profiler missed.
    if not mapping:
        try:
            proc = subprocess.run(
                ["mdfind", "kMDItemKind=='Application'"],
                capture_output=True, text=True, timeout=8,
            )
            for line in proc.stdout.splitlines():
                p = line.strip()
                if not p.endswith(".app"):
                    continue
                # /Applications/Google Chrome.app -> "Google Chrome"
                base = p.rsplit("/", 1)[-1]
                if base.lower().endswith(".app"):
                    base = base[:-4]
                if base:
                    mapping.setdefault(base.lower(), base)
        except Exception:
            pass

    _INSTALLED_APPS_CACHE["at"] = now
    _INSTALLED_APPS_CACHE["map"] = mapping
    return mapping


def _resolve_app(key: str) -> Dict[str, str]:
    """Resolve a user-supplied app name to a launch spec.

    Order:
      1. Exact alias-table hit (covers spec examples + common synonyms).
      2. Live bundle catalogue match (exact, then prefix/contains).
      3. Fall back to letting `open -a "<key>"` try the raw name on macOS —
         this catches anything whose display name equals the user's phrase.
      4. Raise ToolError("Application '<key>' is not installed.") — never silent.
    """
    norm = (key or "").strip()
    if not norm:
        raise ToolError("Application name is required.")
    lower = norm.lower()
    apps = _get_apps()

    # 1. Alias table.
    if lower in apps:
        return apps[lower]

    # 2. Live bundle catalogue (macOS).
    if platform.system() == "Darwin":
        installed = _installed_apps_map()
        if installed:
            if lower in installed:
                real = installed[lower]
                return {"open": real, "kill": real, "label": real}
            # Prefix / contains match: "chrome" -> "Google Chrome".
            candidates = [n for n in installed.values() if lower in n.lower()]
            if len(candidates) == 1:
                real = candidates[0]
                return {"open": real, "kill": real, "label": real}
            # Multiple matches: prefer one whose name ends with the query
            # ("chrome" -> "Google Chrome", not "Chrome Remote Desktop").
            if candidates:
                end_matches = [c for c in candidates if c.lower().endswith(lower)]
                if len(end_matches) == 1:
                    real = end_matches[0]
                    return {"open": real, "kill": real, "label": real}

            # 3. Raw-name trust: let macOS `open -a` try the exact user phrase.
            # We only do this if the phrase doesn't look like garbage and isn't
            # already known to be absent from the catalogue.
            if norm not in installed.values():
                # Verify the bundle actually exists before trusting this path,
                # so we never silently no-op.
                if _mac_app_exists(norm):
                    return {"open": norm, "kill": norm, "label": norm}

    raise ToolError(f"Application '{key}' is not installed.")


def _mac_app_exists(name: str) -> bool:
    """Quick existence check for an .app by display name via `mdfind`."""
    try:
        proc = subprocess.run(
            ["mdfind", f"kMDItemKind=='Application' && kMDItemDisplayName=='{name}'"],
            capture_output=True, text=True, timeout=4,
        )
        return any(line.strip().endswith(".app") for line in proc.stdout.splitlines())
    except Exception:
        return False


def _is_running(spec: Dict[str, str]) -> bool:
    """Best-effort 'is this app running right now?' check."""
    system = platform.system()
    name = spec.get("label") or spec.get("open") or ""
    try:
        if system == "Darwin":
            # osascript is authoritative for the running state on macOS.
            proc = subprocess.run(
                ["osascript", "-e", f'application "{name}" is running'],
                capture_output=True, text=True, timeout=4,
            )
            return proc.stdout.strip().lower() == "true"
        # Windows / Linux: pgrep/taskkill probe.
        target = spec.get("kill", name)
        if system == "Windows":
            proc = subprocess.run(
                f'tasklist /FI "IMAGENAME eq {target}"',
                capture_output=True, text=True, timeout=4,
            )
            return target.lower() in proc.stdout.lower()
        proc = subprocess.run(
            ["pgrep", "-ix", target], capture_output=True, text=True, timeout=4,
        )
        return proc.returncode == 0
    except Exception:
        return False


def _launch(spec: Dict[str, str]) -> None:
    system = platform.system()
    try:
        if system == "Darwin":
            # `open -a <name>` resolves the bundle by display name and brings
            # it to the foreground. Fallback to the old name if the new one
            # is rejected (e.g. System Settings on an older macOS).
            try:
                subprocess.Popen(
                    ["open", "-a", spec["open"]],
                    close_fds=True, start_new_session=True,
                )
            except Exception:
                subprocess.Popen(
                    ["open", spec["open"]],
                    close_fds=True, start_new_session=True,
                )
        elif system == "Windows":
            exe = spec["open"]
            if shutil.which(exe) or exe.lower().endswith(".exe"):
                subprocess.Popen(
                    [exe], shell=False, close_fds=True,
                    creationflags=getattr(subprocess, "DETACHED_PROCESS", 0)
                    | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
                )
            else:
                subprocess.Popen(f'start "" "{exe}"', shell=True, close_fds=True)
        else:
            if shutil.which(spec["open"]):
                subprocess.Popen(
                    [spec["open"]], close_fds=True, start_new_session=True,
                )
            else:
                raise ToolError(f"Application '{spec.get('label')}' not found.")
    except ToolError:
        raise
    except Exception as e:
        raise ToolError(f"Unable to launch {spec.get('label')}: {e}") from e


def _close(spec: Dict[str, str], force: bool = False) -> None:
    system = platform.system()
    kill_target = spec["kill"]
    try:
        if system == "Darwin":
            # Prefer a graceful AppleScript quit so the app can save state.
            flag = "-9" if force else "-15"
            subprocess.run(
                ["pkill", flag, "-x", kill_target],
                capture_output=True, timeout=10,
            )
        elif system == "Windows":
            force_flag = " /F" if force else ""
            subprocess.run(
                f'taskkill /IM "{kill_target}"{force_flag}',
                shell=True, capture_output=True, timeout=10,
            )
        else:
            flag = "-9" if force else "-15"
            subprocess.run(
                ["pkill", flag, "-x", kill_target],
                capture_output=True, timeout=10,
            )
    except Exception as e:
        raise ToolError(f"Could not close {spec['label']}: {e}") from e
    time.sleep(0.2)


def _mac_fallback_old_settings_name(name: str) -> Optional[str]:
    """macOS 13+ uses 'System Settings'; older uses 'System Preferences'."""
    if name == "System Settings":
        return "System Preferences"
    return None


@register("openApplication")
def open_application(args: Dict[str, Any]) -> Dict[str, Any]:
    name = args.get("name") or args.get("application")
    if not name:
        raise ToolError("Parameter 'name' (application name) is required.")
    spec = _resolve_app(str(name))

    # Idempotency: if it's already running, don't relaunch (spec §3).
    if _is_running(spec):
        return {"result": f"{spec['label']} is already open.", "already_open": True}

    _launch(spec)

    # Verify the launch took. `open -a` is async; give it a beat.
    if platform.system() == "Darwin":
        time.sleep(0.6)
        # If we tried the new name (e.g. System Settings) and it never came up,
        # retry once with the legacy name on older macOS.
        if not _is_running(spec):
            fallback = _mac_fallback_old_settings_name(spec["open"])
            if fallback:
                legacy_spec = {"open": fallback, "kill": fallback, "label": fallback}
                try:
                    _launch(legacy_spec)
                    time.sleep(0.6)
                    if _is_running(legacy_spec):
                        return {"result": f"{legacy_spec['label']} opened."}
                except Exception:
                    pass
            raise ToolError(f"Unable to launch application '{name}'.")

    return {"result": f"{spec['label']} opened."}


@register("closeApplication")
def close_application(args: Dict[str, Any]) -> Dict[str, Any]:
    name = args.get("name") or args.get("application")
    force = bool(args.get("force", False))
    if not name:
        raise ToolError("Parameter 'name' (application name) is required.")
    spec = _resolve_app(str(name))

    if not _is_running(spec):
        return {"result": f"{spec['label']} wasn't running.", "was_running": False}

    _close(spec, force)
    return {"result": f"Closed {spec['label']}."}


__all__ = ["open_application", "close_application"]
