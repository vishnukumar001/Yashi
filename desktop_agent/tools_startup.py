r"""
Auto-start management for Yashi.

macOS: uses a LaunchAgent plist in ~/Library/LaunchAgents.
Windows: uses a Run registry key (HKCU\...\Run).
Other platforms: returns a clear "unsupported" message.
"""

from __future__ import annotations

import os
import platform
import subprocess
from pathlib import Path
from typing import Any, Dict

from .registry import ToolError, register

PLIST_NAME = "com.yashi.desktop.agent.plist"
LEGACY_PLIST_NAME = "com.vexa.desktop.agent.plist"
LAUNCH_AGENTS_DIR = Path(os.path.expanduser("~")) / "Library" / "LaunchAgents"


def _is_macos() -> bool:
    return platform.system() == "Darwin"


def _is_windows() -> bool:
    return platform.system() == "Windows"


def _plist_path() -> Path:
    return LAUNCH_AGENTS_DIR / PLIST_NAME


def _legacy_plist_path() -> Path:
    return LAUNCH_AGENTS_DIR / LEGACY_PLIST_NAME


def _python_path() -> str:
    """Find a usable Python interpreter."""
    import shutil
    for candidate in ["python3", "python"]:
        if shutil.which(candidate):
            return candidate
    raise ToolError("No Python interpreter found on this system.")


def _write_launch_agent() -> Path:
    """Create a LaunchAgent plist that starts the desktop agent on login."""
    LAUNCH_AGENTS_DIR.mkdir(parents=True, exist_ok=True)
    py = _python_path()
    plist = _plist_path()
    content = f"""\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.yashi.desktop.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>{py}</string>
        <string>-m</string>
        <string>uvicorn</string>
        <string>desktop_agent.main:app</string>
        <string>--host</string>
        <string>127.0.0.1</string>
        <string>--port</string>
        <string>8765</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <false/>
    <key>StandardOutPath</key>
    <string>/tmp/yashi-agent.stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/yashi-agent.stderr.log</string>
</dict>
</plist>
"""
    plist.write_text(content, encoding="utf-8")
    # Clean up legacy plist if present
    legacy = _legacy_plist_path()
    if legacy.exists():
        try:
            subprocess.run(["launchctl", "unload", str(legacy)], capture_output=True, timeout=10)
            legacy.unlink()
        except Exception:
            pass
    # Load the agent so launchd picks it up immediately.
    subprocess.run(["launchctl", "load", str(plist)], capture_output=True, timeout=10)
    return plist


def _remove_launch_agent() -> bool:
    removed = False
    for p in [_plist_path(), _legacy_plist_path()]:
        if p.exists():
            try:
                subprocess.run(["launchctl", "unload", str(p)], capture_output=True, timeout=10)
            except Exception:
                pass
            try:
                p.unlink()
                removed = True
            except Exception:
                pass
    return removed


@register("enableAutoStart")
def enable_auto_start(args: Dict[str, Any]) -> Dict[str, Any]:
    """Enable the desktop agent to start automatically on login."""
    if _is_macos():
        try:
            plist = _write_launch_agent()
            return {
                "result": "Auto-start enabled. Yashi agent will launch on next macOS login.",
                "enabled": True,
                "plist": str(plist),
            }
        except Exception as e:
            raise ToolError(f"Could not create LaunchAgent: {e}") from e
    elif _is_windows():
        try:
            import winreg
            RUN_KEY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"
            key = winreg.CreateKeyEx(
                winreg.HKEY_CURRENT_USER, RUN_KEY_PATH, 0,
                winreg.KEY_SET_VALUE | winreg.KEY_READ,
            )
            py = _python_path()
            winreg.SetValueEx(key, "Yashi", 0, winreg.REG_SZ, f'"{py}" -m uvicorn desktop_agent.main:app --host 127.0.0.1 --port 8765')
            try:
                winreg.DeleteValue(key, "VEXA")
            except Exception:
                pass
            key.Close()
            return {
                "result": "Auto-start enabled. Yashi agent will launch on next Windows login.",
                "enabled": True,
            }
        except ImportError:
            raise ToolError("Auto-start on Windows requires pywin32.")
        except Exception as e:
            raise ToolError(f"Could not write startup registry entry: {e}") from e
    else:
        raise ToolError("Auto-start is only supported on macOS and Windows.")


@register("disableAutoStart")
def disable_auto_start(args: Dict[str, Any]) -> Dict[str, Any]:
    """Disable auto-start of the desktop agent."""
    if _is_macos():
        removed = _remove_launch_agent()
        if not removed:
            return {"result": "Auto-start was already disabled.", "enabled": False}
        return {
            "result": "Auto-start disabled. Yashi agent will no longer launch on login.",
            "enabled": False,
        }
    elif _is_windows():
        try:
            import winreg
            RUN_KEY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER, RUN_KEY_PATH, 0, winreg.KEY_SET_VALUE
            ) as key:
                try:
                    winreg.DeleteValue(key, "Yashi")
                except FileNotFoundError:
                    pass
                try:
                    winreg.DeleteValue(key, "VEXA")
                except FileNotFoundError:
                    pass
            return {
                "result": "Auto-start disabled. Yashi agent will no longer launch on login.",
                "enabled": False,
            }
        except FileNotFoundError:
            return {"result": "Auto-start was already disabled.", "enabled": False}
        except ImportError:
            return {"result": "Auto-start was already disabled.", "enabled": False}
        except Exception as e:
            raise ToolError(f"Could not remove startup entry: {e}") from e
    else:
        raise ToolError("Auto-start is only supported on macOS and Windows.")


@register("getAutoStartStatus")
def get_auto_start_status(args: Dict[str, Any]) -> Dict[str, Any]:
    """Report whether auto-start is currently enabled."""
    if _is_macos():
        plist = _plist_path()
        legacy = _legacy_plist_path()
        enabled = plist.exists() or legacy.exists()
        active_plist = str(plist if plist.exists() else legacy)
        return {
            "result": (
                "Auto-start is ENABLED. Yashi agent launches on macOS login."
                if enabled else "Auto-start is DISABLED."
            ),
            "enabled": enabled,
            "plist": active_plist,
            "platform": platform.system(),
        }
    elif _is_windows():
        try:
            import winreg
            RUN_KEY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER, RUN_KEY_PATH, 0, winreg.KEY_READ
            ) as key:
                value = None
                for k in ["Yashi", "VEXA"]:
                    try:
                        value, _ = winreg.QueryValueEx(key, k)
                        break
                    except FileNotFoundError:
                        pass
                if value is not None:
                    return {
                        "result": "Auto-start is ENABLED. Yashi agent launches on Windows login.",
                        "enabled": True,
                        "launcher": value,
                        "platform": platform.system(),
                    }
        except (FileNotFoundError, ImportError):
            pass
        except Exception:
            pass
        return {
            "result": "Auto-start is DISABLED.",
            "enabled": False,
            "platform": platform.system(),
        }
    else:
        return {
            "result": "Auto-start is only supported on macOS and Windows.",
            "enabled": False,
            "platform": platform.system(),
        }
