"""
PC control: system volume and (gated) power actions.

Volume:
  macOS  : uses osascript (AppleScript) for precise scalar control.
  Windows: uses pycaw + comtypes when available, media-key fallback otherwise.

Power:
  shutdown / restart / sleep / lock are DANGEROUS and require the two-step
  confirmation flow (tools_confirmation). `executePowerAction` consumes the
  token before running anything destructive.

Brightness:
  Uses screen_brightness_control when available (cross-platform). Falls back
  gracefully when unavailable.
"""

from __future__ import annotations

import platform
import subprocess
from typing import Any, Dict, Optional

from .registry import ToolError, register
from .tools_confirmation import ACTION_LABEL, consume_token


# --- Volume backend (lazy) ----------------------------------------------------

_vol_backend = None  # one of "osascript" | "pycaw" | "media_keys" | None


def _get_volume_interface():
    global _vol_backend
    if _vol_backend is None:
        system = platform.system()
        if system == "Darwin":
            _vol_backend = "osascript"
        elif system == "Windows":
            try:
                from ctypes import cast, POINTER
                import comtypes  # noqa: F401
                from pycaw.pycaw import AudioUtilities, IAudioEndpointVolume
                devices = AudioUtilities.GetSpeakers()
                interface = devices.Activate(
                    IAudioEndpointVolume._iid_, comtypes.CLSCTX_ALL, None
                )
                volume = cast(interface, POINTER(IAudioEndpointVolume))
                _vol_backend = "pycaw"
                _VOL_CACHE["iface"] = volume
            except Exception:
                _vol_backend = "media_keys"
        else:
            _vol_backend = "media_keys"
    return _vol_backend


_VOL_CACHE: Dict[str, Any] = {}


def _current_volume() -> float:
    """Returns current master volume in 0.0..1.0 (best effort)."""
    backend = _get_volume_interface()
    if backend == "osascript":
        try:
            out = subprocess.check_output(
                ["osascript", "-e", "output volume of (get volume settings)"],
                text=True, timeout=5,
            ).strip()
            return int(out) / 100.0
        except Exception:
            return 0.5
    if backend == "pycaw":
        try:
            iface = _VOL_CACHE.get("iface")
            if iface:
                return float(iface.GetMasterVolumeLevelScalar())
        except Exception:
            pass
    return 0.5


def _set_volume_scalar(value: float) -> None:
    value = max(0.0, min(1.0, float(value)))
    backend = _get_volume_interface()
    if backend == "osascript":
        pct = int(round(value * 100))
        subprocess.run(
            ["osascript", "-e", f"set volume output volume {pct}"],
            check=False, timeout=5,
        )
        return
    if backend == "pycaw":
        try:
            iface = _VOL_CACHE.get("iface")
            if iface:
                iface.SetMasterVolumeLevelScalar(value, None)
                return
        except Exception:
            pass
    _set_volume_via_keys(value)


def _set_volume_via_keys(target: float) -> None:
    """Approximate target volume by stepping media keys. Coarse but reliable."""
    try:
        import pyautogui
        current = _current_volume()
        diff = target - current
        steps = int(abs(diff) / 0.02) + 1
        key = "volumeup" if diff > 0 else "volumedown"
        for _ in range(min(steps, 50)):
            pyautogui.press(key)
            import time
            time.sleep(0.01)
    except Exception:
        pass


def _toggle_mute() -> bool:
    backend = _get_volume_interface()
    if backend == "osascript":
        try:
            out = subprocess.check_output(
                ["osascript", "-e", "output muted of (get volume settings)"],
                text=True, timeout=5,
            ).strip()
            is_muted = out.lower() == "true"
            if is_muted:
                subprocess.run(["osascript", "-e", "set volume output muted false"], check=False)
            else:
                subprocess.run(["osascript", "-e", "set volume output muted true"], check=False)
            return not is_muted
        except Exception:
            pass
    try:
        import pyautogui
        pyautogui.press("volumemute")
        import time
        time.sleep(0.05)
    except Exception:
        pass
    return False


# --- Tool handlers -----------------------------------------------------------

@register("volumeUp")
def volume_up(args: Dict[str, Any]) -> Dict[str, Any]:
    step = float(args.get("amount", 0.10))
    new = min(1.0, _current_volume() + step)
    _set_volume_scalar(new)
    return {"result": f"Volume increased to {int(new * 100)}%."}


@register("volumeDown")
def volume_down(args: Dict[str, Any]) -> Dict[str, Any]:
    step = float(args.get("amount", 0.10))
    new = max(0.0, _current_volume() - step)
    _set_volume_scalar(new)
    return {"result": f"Volume decreased to {int(new * 100)}%."}


@register("setVolume")
def set_volume(args: Dict[str, Any]) -> Dict[str, Any]:
    if "percent" in args:
        pct = float(args["percent"])
    elif "level" in args:
        pct = float(args["level"])
    else:
        raise ToolError("Parameter 'percent' (0-100) is required.")
    pct = max(0.0, min(100.0, pct))
    _set_volume_scalar(pct / 100.0)
    return {"result": f"Volume set to {int(pct)}%."}


@register("muteToggle")
def mute_toggle(args: Dict[str, Any]) -> Dict[str, Any]:
    muted = _toggle_mute()
    return {"result": "Muted." if muted else "Unmuted."}


# --- Gated power actions -----------------------------------------------------

def _run_power(action: str) -> str:
    """Execute the actual OS power command. Caller must have confirmed first."""
    system = platform.system()
    if action == "lock":
        if system == "Darwin":
            subprocess.run(
                ["/System/Library/CoreServices/Menu Extras/User.menu/Contents/Resources/CGSession", "-suspend"],
                check=False, timeout=10,
            )
            return "Computer locked."
        elif system == "Windows":
            import ctypes
            ctypes.windll.user32.LockWorkStation()
            return "Computer locked."
        else:
            subprocess.run(["xdg-screensaver", "lock"], check=False, timeout=10)
            return "Screen locked."
    if action == "sleep":
        if system == "Darwin":
            subprocess.run(["pmset", "sleepnow"], check=False, timeout=10)
            return "Computer going to sleep."
        elif system == "Windows":
            subprocess.run(
                ["rundll32.exe", "powrprof.dll,SetSuspendState", "0,1,0"],
                check=False, timeout=10,
            )
            return "Computer going to sleep."
        else:
            subprocess.run(["systemctl", "suspend"], check=False)
            return "Computer going to sleep."
    if action == "restart":
        if system == "Darwin":
            subprocess.run(["sudo", "reboot"], check=False, timeout=10)
            return "Computer restarting."
        elif system == "Windows":
            subprocess.run(["shutdown", "/r", "/t", "5"], check=False, timeout=10)
            return "Computer restarting in 5 seconds."
        else:
            subprocess.run(["shutdown", "-r", "now"], check=False)
            return "Computer restarting."
    if action == "shutdown":
        if system == "Darwin":
            subprocess.run(["sudo", "shutdown", "-h", "now"], check=False, timeout=10)
            return "Computer shutting down."
        elif system == "Windows":
            subprocess.run(["shutdown", "/s", "/t", "10"], check=False, timeout=10)
            return "Computer shutting down in 10 seconds."
        else:
            subprocess.run(["shutdown", "-h", "now"], check=False)
            return "Computer shutting down."
    raise ToolError(f"Unknown power action '{action}'.")


@register("executePowerAction")
def execute_power_action(args: Dict[str, Any]) -> Dict[str, Any]:
    action = (args.get("action") or "").strip().lower()
    token: Optional[str] = args.get("execute_token")

    from .tools_confirmation import DANGEROUS_ACTIONS
    if action not in DANGEROUS_ACTIONS:
        raise ToolError(
            f"Unknown power action '{action}'. Valid: {', '.join(sorted(DANGEROUS_ACTIONS))}."
        )

    consume_token(action, token)
    msg = _run_power(action)
    return {"result": msg, "action": action}


@register("_cancelPowerTimer")
def _cancel(args: Dict[str, Any]) -> Dict[str, Any]:
    system = platform.system()
    if system == "Windows":
        subprocess.run(["shutdown", "/a"], check=False)
    else:
        subprocess.run(["shutdown", "-c"], check=False)
    return {"result": "Cancelled pending shutdown/restart timer."}


# --- Brightness control ------------------------------------------------------

_sbc = None


def _brightness_backend():
    global _sbc
    if _sbc is not None:
        return _sbc if _sbc is not False else None
    try:
        import screen_brightness_control as sbc
        _sbc = sbc
        return sbc
    except Exception:
        _sbc = False
        return None


def _current_brightness() -> int:
    sbc = _brightness_backend()
    if sbc is not None:
        try:
            vals = sbc.get_brightness()
            if vals:
                return int(round(sum(vals) / len(vals)))
        except Exception:
            pass
    raise ToolError("Brightness control is not supported on this device.")


def _set_brightness(pct: float) -> int:
    pct = max(0.0, min(100.0, pct))
    sbc = _brightness_backend()
    if sbc is not None:
        try:
            sbc.set_brightness(int(pct))
            return int(pct)
        except Exception as e:
            raise ToolError(f"Could not set brightness: {e}") from e
    raise ToolError("Brightness control is not supported on this device.")


@register("brightnessUp")
def brightness_up(args: Dict[str, Any]) -> Dict[str, Any]:
    step = float(args.get("amount", 10))
    current = _current_brightness()
    new = _set_brightness(current + step)
    return {"result": f"Brightness increased to {new}%.", "brightness": new}


@register("brightnessDown")
def brightness_down(args: Dict[str, Any]) -> Dict[str, Any]:
    step = float(args.get("amount", 10))
    current = _current_brightness()
    new = _set_brightness(current - step)
    return {"result": f"Brightness decreased to {new}%.", "brightness": new}


@register("setBrightness")
def set_brightness(args: Dict[str, Any]) -> Dict[str, Any]:
    if "percent" in args:
        pct = float(args["percent"])
    elif "level" in args:
        pct = float(args["level"])
    else:
        raise ToolError("Parameter 'percent' (0-100) is required.")
    new = _set_brightness(pct)
    return {"result": f"Brightness set to {new}%.", "brightness": new}


__all__ = [
    "volume_up", "volume_down", "set_volume", "mute_toggle",
    "execute_power_action", "brightness_up", "brightness_down", "set_brightness",
]
