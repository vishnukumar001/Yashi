"""
Window management: minimize / maximize / close the active window or switch apps.

macOS: uses AppleScript (osascript) for window manipulation.
Windows: uses win32gui/pygetwindow with graceful degradation.
"""

from __future__ import annotations

import logging
import platform
import subprocess
import time
from typing import Any, Dict, Optional

from .registry import ToolError, register
from .tools_applications import _resolve_app
from .tools_applications import _is_running as _app_is_running
from .tools_applications import _launch as _launch_app

log = logging.getLogger("yashi.desktop")


def _is_macos() -> bool:
    return platform.system() == "Darwin"


def _is_windows() -> bool:
    return platform.system() == "Windows"


def _osascript(script: str, timeout: float = 5) -> str:
    try:
        proc = subprocess.run(
            ["osascript", "-e", script],
            capture_output=True, text=True, timeout=timeout,
        )
    except Exception as e:
        log.error("OSASCRIPT_EXEC_FAILED: %s", e)
        raise ToolError(f"AppleScript failed to run: {e}")
    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        log.warning("OSASCRIPT_NONZERO_EXIT code=%s stderr=%s", proc.returncode, stderr)
        if "not allowed assistive access" in stderr.lower() or "-1743" in stderr:
            raise ToolError(
                "Yashi doesn't have Accessibility permission, so it can't see or "
                "control other apps' windows. Open System Settings > Privacy & "
                "Security > Accessibility and enable it for the Yashi desktop "
                "agent, then try again."
            )
        raise ToolError(f"AppleScript failed: {stderr or 'unknown error'}")
    return (proc.stdout or "").strip()


_ACCESSIBILITY_OK: Optional[bool] = None


def _accessibility_permission_granted() -> bool:
    """Best-effort, cached check for the Accessibility (TCC) permission that
    System Events window-introspection AppleScript requires. Lets callers
    distinguish 'app not found' from 'we're not allowed to look'."""
    global _ACCESSIBILITY_OK
    if _ACCESSIBILITY_OK is not None:
        return _ACCESSIBILITY_OK
    if not _is_macos():
        _ACCESSIBILITY_OK = True
        return True
    try:
        proc = subprocess.run(
            ["osascript", "-e",
             'tell application "System Events" to get name of first process whose frontmost is true'],
            capture_output=True, text=True, timeout=5,
        )
        stderr = (proc.stderr or "").lower()
        _ACCESSIBILITY_OK = proc.returncode == 0 and "not allowed assistive access" not in stderr
    except Exception:
        _ACCESSIBILITY_OK = False
    if not _ACCESSIBILITY_OK:
        log.warning("ACCESSIBILITY_PERMISSION_MISSING — window management tools will misreport as 'not found'.")
    return _ACCESSIBILITY_OK


def _get_foreground_window_title() -> str:
    if _is_macos():
        try:
            return subprocess.check_output(
                [
                    "osascript", "-e",
                    'tell application "System Events" to get name of first application process whose frontmost is true',
                ],
                text=True, timeout=5,
            ).strip()
        except Exception:
            return ""
    if _is_windows():
        try:
            import win32gui
            hwnd = win32gui.GetForegroundWindow()
            return win32gui.GetWindowText(hwnd) if hwnd else ""
        except Exception:
            return ""
    return ""


def _applescript_escape(s: str) -> str:
    """Escape a string for safe interpolation into a double-quoted AppleScript
    literal (backslash and double-quote), so titles containing '"' can't
    break or inject into the script."""
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _find_window_by_title(query: str) -> Optional[str]:
    """Find an app/process name whose window contains query."""
    if _is_macos():
        safe_query = _applescript_escape(query)
        script = f'''
        tell application "System Events"
            set foundApp to ""
            repeat with proc in (every process whose background only is false)
                try
                    set windowName to name of front window of proc
                    if windowName contains "{safe_query}" then
                        set foundApp to name of proc
                        exit repeat
                    end if
                end try
            end repeat
            return foundApp
        end tell
        '''
        try:
            result = _osascript(script, timeout=10)
        except ToolError as e:
            # Propagate distinctly-diagnosed failures (e.g. missing
            # Accessibility permission) instead of masking them as "no match".
            log.warning("FIND_WINDOW_BY_TITLE_FAILED query=%r error=%s", query, e.message)
            raise
        log.info("FIND_WINDOW_BY_TITLE query=%r result=%r", query, result)
        return result if result else None
    if _is_windows():
        try:
            import win32gui
            matches = []
            def cb(hwnd, _):
                if win32gui.IsWindowVisible(hwnd):
                    title = win32gui.GetWindowText(hwnd)
                    if title and query.lower() in title.lower():
                        matches.append(hwnd)
                return True
            win32gui.EnumWindows(cb, None)
            if matches:
                return win32gui.GetWindowText(matches[0])
        except Exception:
            pass
    return None


def _minimize_app(app_name: str) -> None:
    if _is_macos():
        _osascript(f'''
        tell application "{app_name}" to set miniaturized of front window to true
        ''')
    elif _is_windows():
        try:
            import win32gui, win32con
            hwnd = win32gui.GetForegroundWindow()
            win32gui.ShowWindow(hwnd, win32con.SW_MINIMIZE)
        except Exception:
            pass


def _maximize_app(app_name: str) -> None:
    if _is_macos():
        _osascript(f'''
        tell application "System Events"
            tell process "{app_name}"
                set zoomed of front window to true
            end tell
        end tell
        ''')
    elif _is_windows():
        try:
            import win32gui, win32con
            hwnd = win32gui.GetForegroundWindow()
            win32gui.ShowWindow(hwnd, win32con.SW_MAXIMIZE)
        except Exception:
            pass


def _close_app(app_name: str) -> None:
    if _is_macos():
        subprocess.run(["pkill", "-x", app_name], capture_output=True, timeout=10)
    elif _is_windows():
        try:
            import win32gui, win32con
            hwnd = win32gui.GetForegroundWindow()
            win32gui.PostMessage(hwnd, win32con.WM_CLOSE, 0, 0)
        except Exception:
            pass


def _focus_app(app_name: str) -> None:
    if _is_macos():
        _osascript(f'''
        tell application "{app_name}" to activate
        ''')
    elif _is_windows():
        try:
            import win32gui
            hwnd = win32gui.GetForegroundWindow()
            win32gui.SetForegroundWindow(hwnd)
        except Exception:
            pass


def _resolve_target(args: Dict[str, Any]):
    title: Optional[str] = args.get("title") or args.get("application")
    if title:
        # Fast path: if the caller gave an app name (e.g. "Safari") and that
        # app is already running, skip the expensive per-process AppleScript
        # window-title enumeration entirely and act on it directly. This is
        # the common case ("maximize Safari") and was previously always
        # paying the cost of scanning every open process's window title.
        try:
            spec = _resolve_app(str(title))
            if _app_is_running(spec):
                log.info("RESOLVE_TARGET_FAST_PATH title=%r -> %r", title, spec["open"])
                return spec["open"], str(title)
        except ToolError:
            pass  # not a recognized app name — fall through to window search

        found = _find_window_by_title(str(title))
        if not found:
            raise ToolError(f"No visible window with title containing '{title}'.")
        return found, str(title)
    fg = _get_foreground_window_title()
    if not fg:
        raise ToolError("No active window found.")
    return fg, fg


@register("minimizeWindow")
def minimize_window(args: Dict[str, Any]) -> Dict[str, Any]:
    app_name, title = _resolve_target(args)
    _minimize_app(app_name)
    return {"result": f"Minimized window: {title or 'active window'}."}


@register("maximizeWindow")
def maximize_window(args: Dict[str, Any]) -> Dict[str, Any]:
    app_name, title = _resolve_target(args)
    _maximize_app(app_name)
    return {"result": f"Maximized window: {title or 'active window'}."}


@register("closeWindow")
def close_window(args: Dict[str, Any]) -> Dict[str, Any]:
    app_name, title = _resolve_target(args)
    _close_app(app_name)
    return {"result": f"Closed window: {title or 'active window'}."}


@register("switchApplication")
def switch_application(args: Dict[str, Any]) -> Dict[str, Any]:
    """Focus a window by title. Falls back to launching the app if it isn't
    already open, so a model choosing 'switch' when it meant 'open' still
    works. Cycles windows (Cmd+Tab / Alt+Tab) if no title is given."""
    title = args.get("title") or args.get("application")
    log.info("SWITCH_APP_START title=%r", title)

    if title:
        # Fast path: exact running-app-name match — skip the per-process
        # window-title scan entirely (this is what made "switch to Safari"
        # slow even though Safari was already open).
        try:
            fast_spec = _resolve_app(str(title))
            if _app_is_running(fast_spec):
                _focus_app(fast_spec["open"])
                log.info("SWITCH_APP_FAST_PATH title=%r -> %r", title, fast_spec["open"])
                return {"result": f"Switched to: {fast_spec['label']}."}
        except ToolError:
            pass  # not a recognized app name — fall through to window search

        found = _find_window_by_title(str(title))
        log.info("SWITCH_APP_WINDOW_LOOKUP title=%r found=%r", title, found)

        if found:
            _focus_app(found)
            log.info("SWITCH_APP_FOCUSED target=%r", found)
            return {"result": f"Switched to: {str(title)}."}

        # No matching window. Before assuming "not found", rule out a broken
        # Accessibility permission — otherwise this would silently misreport
        # as "not found" even when the app *is* open with a window.
        if not _accessibility_permission_granted():
            log.warning("SWITCH_APP_BLOCKED_NO_ACCESSIBILITY title=%r", title)
            raise ToolError(
                "Yashi can't see other apps' windows because Accessibility "
                "permission hasn't been granted. Open System Settings > "
                "Privacy & Security > Accessibility and enable it for the "
                "Yashi desktop agent, then try again."
            )

        # Genuinely no window for this app. Resolve it the same way
        # openApplication does, and either bring it forward (if it's running
        # but window-less, e.g. a menu-bar app) or launch it outright. This
        # is the fix for the "switchApplication called, nothing happens"
        # bug: the tool now self-heals instead of silently no-opping.
        try:
            spec = _resolve_app(str(title))
        except ToolError:
            log.warning("SWITCH_APP_UNRESOLVABLE title=%r", title)
            raise

        if _app_is_running(spec):
            log.info("SWITCH_APP_RUNNING_NO_WINDOW spec=%r — focusing instead", spec)
            _focus_app(spec["open"])
            return {"result": f"{spec['label']} is running; brought it to the front."}

        log.info("SWITCH_APP_LAUNCH_FALLBACK spec=%r", spec)
        _launch_app(spec)
        return {
            "result": f"{spec['label']} wasn't open, so Yashi opened it instead.",
            "launched_fallback": True,
        }

    # No specific title -> cycle windows.
    try:
        import pyautogui
        if _is_macos():
            pyautogui.hotkey("command", "tab")
        else:
            pyautogui.hotkey("alt", "tab")
        log.info("SWITCH_APP_CYCLED")
        return {"result": "Cycled to the next window."}
    except Exception as e:
        log.error("SWITCH_APP_CYCLE_FAILED: %s", e)
        raise ToolError(f"Could not switch applications: {e}")


__all__ = [
    "minimize_window", "maximize_window", "close_window", "switch_application",
]