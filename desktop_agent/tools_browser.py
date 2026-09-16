"""
Browser automation via the user's REAL, visible browser window.

There is NO separate Playwright/Chromium browser here. Every desktopBrowser*
tool drives the same browser window the user can see (the OS default browser,
opened by `webbrowser.open` / openWebsite). This guarantees:

  - the page Gemini reads  ==  the page the user sees
  - no split-brain, no hidden window, no second browser instance

Mechanism (cross-platform, macOS-first):
  - open URL       : webbrowser.open()  -> real default browser
  - focus window   : AppleScript `activate` (macOS) / OS default (others)
  - click          : pyautogui at coords, or OCR-located text label
  - type           : pyautogui write/typewrite (after focusing the field)
  - navigation     : Cmd+[ / Cmd+] / Cmd+T / Cmd+W / Cmd+L keyboard shortcuts
  - verify state   : read the REAL window URL+title via AppleScript
                     (Safari + Chrome), fall back to readScreen OCR

Response shape is unchanged from the previous Playwright implementation:
every handler returns { result, page_title, page_url, page_text, window_visible }.
Gemini therefore keeps getting the OBSERVE feedback it needs after every step.
"""

from __future__ import annotations

import logging
import platform
import subprocess
import time
import webbrowser
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote_plus

from .registry import ToolError, register

log = logging.getLogger("yashi.desktop.browser")

# How long to wait after opening/focusing before reading back the page state.
# Browsers load asynchronously; without this we'd read the pre-navigation URL.
_SETTLE_SECONDS = 1.5

_IS_MAC = platform.system() == "Darwin"
_MOD = "command" if _IS_MAC else "ctrl"


def _browsers() -> List[str]:
    """Browser process names we can focus/control, best-match first."""
    if _IS_MAC:
        return ["Safari", "Google Chrome", "Chromium", "Microsoft Edge", "Firefox"]
    return ["chrome", "msedge", "firefox"]


# ---------------------------------------------------------------------------
# Logging helper — emits a consistent [BROWSER] line to stdout + the logger so
# the user can watch what Yashi is doing in the agent console.
# ---------------------------------------------------------------------------
def _blog(msg: str, *args: Any) -> None:
    formatted = msg % args if args else msg
    print(f"[BROWSER] {formatted}", flush=True)
    log.info(formatted)


# ---------------------------------------------------------------------------
# Window focus
# ---------------------------------------------------------------------------
def _running_browsers() -> List[str]:
    """Return the browser app names that are currently running (macOS)."""
    if not _IS_MAC:
        return []
    try:
        script = (
            'tell application "System Events" to '
            'get name of every process whose background only is false'
        )
        out = subprocess.run(
            ["osascript", "-e", script],
            capture_output=True, text=True, timeout=5,
        ).stdout.strip()
        running = [n.strip() for n in out.split(",") if n.strip()]
        return [b for b in _browsers() if b in running]
    except Exception:
        return []


def _focus_browser() -> str:
    """Bring a real browser window to the foreground. Returns the app name.

    Prefers an already-running browser; if none is running, opens the default
    browser to about:blank so a window exists to drive.
    """
    if _IS_MAC:
        running = _running_browsers()
        target = running[0] if running else "Safari"
        _blog("focusing window target=%s running=%s", target, running or "none")
        try:
            subprocess.run(
                ["osascript", "-e", f'tell application "{target}" to activate'],
                capture_output=True, text=True, timeout=5,
            )
        except Exception as e:  # noqa: BLE001
            _blog("focus failed: %s", e)
        time.sleep(0.6)
        return target
    # Windows / Linux: rely on webbrowser having opened a window; we can't
    # reliably raise it from here without platform-specific tooling.
    _blog("focus: non-macOS, assuming browser is visible")
    return "default-browser"


def _frontmost_is_browser() -> bool:
    """True if the currently focused app is one of our known browsers."""
    if not _IS_MAC:
        return True  # best-effort: assume visible where we can't introspect
    try:
        script = (
            'tell application "System Events" to '
            'get name of first application process whose frontmost is true'
        )
        out = subprocess.run(
            ["osascript", "-e", script],
            capture_output=True, text=True, timeout=4,
        ).stdout.strip()
        return out in _browsers()
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Real page-state observation
# ---------------------------------------------------------------------------
def _mac_browser_url_title(app: str) -> Tuple[Optional[str], Optional[str]]:
    """Read the URL and title of the front tab of a running browser (macOS)."""
    if app == "Safari":
        script = '''
        tell application "Safari"
            if (count of windows) is 0 then return ""
            set t to current tab of front window
            return (URL of t) & linefeed & (name of t)
        end tell
        '''
    elif app == "Google Chrome":
        script = '''
        tell application "Google Chrome"
            if (count of windows) is 0 then return ""
            set t to active tab of front window
            return (URL of t) & linefeed & (title of t)
        end tell
        '''
    else:
        return None, None
    try:
        out = subprocess.run(
            ["osascript", "-e", script],
            capture_output=True, text=True, timeout=5,
        ).stdout.strip()
        if not out:
            return None, None
        url, _, title = out.partition("\n")
        return url.strip() or None, title.strip() or None
    except Exception:
        return None, None


def _read_real_page_state() -> Dict[str, Any]:
    """Return {url, title, text} from the REAL browser window.

    Falls back to readScreen OCR when the URL can't be read directly
    (unknown browser, or the user is on Windows/Linux).
    """
    url: Optional[str] = None
    title: Optional[str] = None

    if _IS_MAC:
        for app in _running_browsers():
            u, t = _mac_browser_url_title(app)
            if u:
                url, title = u, t
                break

    # OCR fallback / supplement for visible text (always available).
    text = _ocr_visible_text()

    return {
        "url": url or "",
        "title": title or "",
        "text": text,
    }


def _ocr_visible_text() -> str:
    """OCR the active window via the existing readScreen infrastructure."""
    try:
        # Imported lazily so a missing pytesseract doesn't break import.
        from .tools_screenshot import _capture, _active_window_bbox, _capture_region, _run_ocr, _trim_ocr
        bbox = _active_window_bbox()
        img = _capture_region(bbox) if bbox else _capture()
        raw = _run_ocr(img)
        return _trim_ocr(raw, 1800) or "(no readable text)"
    except ToolError as e:
        return f"(OCR unavailable: {e.message})"
    except Exception as e:  # noqa: BLE001
        return f"(OCR failed: {e})"


def _merge_state(result: Dict[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
    """Attach real-window page state to a tool result dict."""
    result["page_title"] = state.get("title", "")
    result["page_url"] = state.get("url", "")
    result["page_text"] = state.get("text", "")
    result["window_visible"] = _frontmost_is_browser()
    return result


# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------
def _normalize_url(raw: str) -> str:
    url = (raw or "").strip()
    if not url:
        raise ToolError("Empty URL.")
    if "://" not in url:
        url = "https://" + url
    return url


def _open_in_real_browser(url: str) -> None:
    """Open a URL in the OS default browser (the window the user sees)."""
    ok = webbrowser.open(url, new=2)
    if not ok:
        raise ToolError(f"Failed to open default browser for {url}.")
    _blog("opened in real browser url=%s", url)


_SEARCH_ENGINES = {
    "google": "https://www.google.com/search?q={q}",
    "youtube": "https://www.youtube.com/results?search_query={q}",
    "github": "https://github.com/search?q={q}",
    "duckduckgo": "https://duckduckgo.com/?q={q}",
    "bing": "https://www.bing.com/search?q={q}",
}


def _build_search_url(engine: str, query: str) -> str:
    e = (engine or "google").strip().lower()
    tmpl = _SEARCH_ENGINES.get(e)
    if not tmpl:
        raise ToolError(
            f"Unsupported engine '{engine}'. Choose from "
            f"{', '.join(sorted(_SEARCH_ENGINES))}."
        )
    return tmpl.format(q=quote_plus(query))


# ---------------------------------------------------------------------------
# OS-level input: click + type
# ---------------------------------------------------------------------------
def _click_at(x: int, y: int) -> None:
    try:
        import pyautogui
        pyautogui.click(x=int(x), y=int(y))
        _blog("click at (%s, %s)", x, y)
    except Exception as e:  # noqa: BLE001
        raise ToolError(f"Click at ({x},{y}) failed: {e}")


def _click_text(label: str) -> bool:
    """Find a visible text label via OCR and click its bounding-box center.

    Returns True if a click was made, False if the label wasn't found.
    """
    box = _locate_text_bbox(label)
    if not box:
        return False
    (l, t, r, b) = box
    _click_at((l + r) // 2, (t + b) // 2)
    return True


def _locate_text_bbox(label: str) -> Optional[Tuple[int, int, int, int]]:
    """Return (left, top, right, bottom) of `label` on screen, or None."""
    label_l = (label or "").strip().lower()
    if not label_l:
        return None
    try:
        from .tools_screenshot import _capture
        import pytesseract
        img = _capture()
        data = pytesseract.image_to_data(img, output_type=pytesseract.Output.DICT)
        n = len(data.get("text", []))
        # Group consecutive words whose joined text contains the label.
        # Tesseract returns one entry per word; we look for any window of
        # up to 8 consecutive non-empty words whose concatenation matches.
        words: List[Tuple[str, int, int, int, int]] = []  # text,l,t,r,b
        for i in range(n):
            w = (data["text"][i] or "").strip()
            if not w:
                continue
            words.append((
                w,
                int(data["left"][i]),
                int(data["top"][i]),
                int(data["left"][i]) + int(data["width"][i]),
                int(data["top"][i]) + int(data["height"][i]),
            ))
        # Try the whole phrase first, then progressively shorter prefixes.
        for span in range(min(8, len(words)), 0, -1):
            for start in range(0, len(words) - span + 1):
                chunk = words[start:start + span]
                joined = " ".join(c[0] for c in chunk).lower()
                if label_l in joined:
                    l = min(c[1] for c in chunk)
                    t = min(c[2] for c in chunk)
                    r = max(c[3] for c in chunk)
                    b = max(c[4] for c in chunk)
                    return (l, t, r, b)
    except Exception as e:  # noqa: BLE001
        _blog("locate_text failed: %s", e)
    return None


def _type_text(text: str) -> None:
    try:
        import pyautogui
        # write() handles unicode; typewrite is ASCII-only.
        pyautogui.write(str(text), interval=0.01)
        _blog("typed %d chars", len(str(text)))
    except Exception as e:  # noqa: BLE001
        raise ToolError(f"Type failed: {e}")


def _hotkey(*keys: str) -> None:
    try:
        import pyautogui
        pyautogui.hotkey(*keys)
    except Exception as e:  # noqa: BLE001
        raise ToolError(f"Keystroke {keys} failed: {e}")


# ---------------------------------------------------------------------------
# Handlers — same names + response shape as before, OS-driven.
# ---------------------------------------------------------------------------
@register("desktopBrowserOpen")
def browser_open(args: Dict[str, Any]) -> Dict[str, Any]:
    url = _normalize_url(args.get("url") or "https://www.google.com")
    _blog("action=open url=%s", url)
    _open_in_real_browser(url)
    time.sleep(_SETTLE_SECONDS)
    _focus_browser()
    state = _read_real_page_state()
    _blog("verification url=%s title=%s", state.get("url"), state.get("title"))
    return _merge_state({"result": f"Opened {url}."}, state)


@register("desktopBrowserNavigate")
def browser_navigate(args: Dict[str, Any]) -> Dict[str, Any]:
    # Alias of desktopBrowserOpen.
    return browser_open(args)


@register("desktopBrowserOpenTab")
def browser_open_tab(args: Dict[str, Any]) -> Dict[str, Any]:
    url = _normalize_url(args.get("url") or "about:blank")
    _blog("action=open_tab url=%s", url)
    _focus_browser()
    _hotkey(_MOD, "t")
    time.sleep(0.5)
    if url != "about:blank":
        # Focus the address bar in the new tab and navigate there.
        _hotkey(_MOD, "l")
        time.sleep(0.2)
        _type_text(url)
        _hotkey("return")
        time.sleep(_SETTLE_SECONDS)
    state = _read_real_page_state()
    _blog("verification url=%s title=%s", state.get("url"), state.get("title"))
    return _merge_state({"result": f"New tab opened at {url}."}, state)


@register("desktopBrowserCloseTab")
def browser_close_tab(args: Dict[str, Any]) -> Dict[str, Any]:
    _blog("action=close_tab")
    _focus_browser()
    _hotkey(_MOD, "w")
    time.sleep(0.6)
    state = _read_real_page_state()
    return _merge_state({"result": "Closed the active tab."}, state)


@register("desktopBrowserSearch")
def browser_search(args: Dict[str, Any]) -> Dict[str, Any]:
    query = args.get("query") or args.get("q")
    engine = (args.get("engine") or "google").strip().lower()
    if not query:
        raise ToolError("Parameter 'query' is required.")
    url = _build_search_url(engine, str(query))
    _blog("action=search engine=%s query=%r", engine, query)
    _open_in_real_browser(url)
    time.sleep(_SETTLE_SECONDS)
    _focus_browser()
    state = _read_real_page_state()
    verification = (
        "Search results loaded." if "search" in state.get("url", "")
        or "results" in state.get("url", "") else "Page loaded."
    )
    _blog("verification url=%s title=%s msg=%s",
          state.get("url"), state.get("title"), verification)
    return _merge_state(
        {"result": f"Searched {engine} for '{query}'. {verification}"},
        state,
    )


@register("desktopBrowserClick")
def browser_click(args: Dict[str, Any]) -> Dict[str, Any]:
    """Click in the visible browser by coordinates OR by visible text label.

    Since there is no DOM access (no Playwright), `selector` is interpreted as
    either text to find on screen, or ignored in favor of `text`/`x`/`y`.
    """
    x = args.get("x")
    y = args.get("y")
    text = args.get("text") or args.get("selector")
    _blog("action=click text=%r coords=(%s,%s)", text, x, y)
    _focus_browser()
    time.sleep(0.3)
    if x is not None and y is not None:
        _click_at(int(x), int(y))
    elif text:
        if not _click_text(str(text)):
            raise ToolError(
                f"Could not find visible text matching {text!r} on screen. "
                "Try scrolling, or pass explicit x/y coordinates."
            )
    else:
        raise ToolError("Provide 'text' (label to click) or 'x' and 'y' coordinates.")
    # Wait for any click-triggered navigation.
    time.sleep(_SETTLE_SECONDS)
    state = _read_real_page_state()
    _blog("verification url=%s title=%s", state.get("url"), state.get("title"))
    return _merge_state({"result": f"Clicked {text or (x, y)}."}, state)


@register("desktopBrowserType")
def browser_type(args: Dict[str, Any]) -> Dict[str, Any]:
    """Type text into the focused field in the visible browser.

    By default focuses the address bar (Cmd/Ctrl+L). Pass `field: "find"` to
    focus the in-page find bar instead, or `field: "search"` to attempt an
    OCR-based click on a search box first.
    """
    text = args.get("text")
    if not text:
        raise ToolError("Parameter 'text' is required.")
    field = (args.get("field") or "address").strip().lower()
    clear_first = bool(args.get("clear", True))
    _blog("action=type field=%s len=%d", field, len(str(text)))
    _focus_browser()
    time.sleep(0.3)
    if field == "find":
        _hotkey(_MOD, "f")
    elif field == "search":
        if not _click_text("search") and not _click_text("Search"):
            # Fall back to the address bar.
            _hotkey(_MOD, "l")
    else:  # address bar
        _hotkey(_MOD, "l")
    time.sleep(0.3)
    if clear_first:
        _hotkey(_MOD, "a")
        _hotkey("delete")
    _type_text(str(text))
    submit = bool(args.get("submit", True))
    if submit:
        _hotkey("return")
        time.sleep(_SETTLE_SECONDS)
    state = _read_real_page_state()
    _blog("verification url=%s title=%s", state.get("url"), state.get("title"))
    return _merge_state({"result": f"Typed {len(str(text))} characters."}, state)


@register("desktopBrowserFillForm")
def browser_fill_form(args: Dict[str, Any]) -> Dict[str, Any]:
    """Best-effort form fill in the visible browser.

    Without DOM access we cannot target fields by CSS selector reliably, so
    each entry is (label_or_selector -> value): for each, we try to click the
    visible label text, then type the value, then Tab to the next field.
    Returns a per-field outcome list.
    """
    fields = args.get("fields")
    submit_sel = args.get("submit")
    if not isinstance(fields, dict) or not fields:
        raise ToolError("Parameter 'fields' (object of label->value) is required.")
    _blog("action=fill_form fields=%d", len(fields))
    _focus_browser()
    time.sleep(0.3)
    outcomes: List[Dict[str, Any]] = []
    filled = 0
    for label, val in fields.items():
        clicked = _click_text(str(label))
        if not clicked:
            # Couldn't find the label — Tab from wherever we are.
            outcomes.append({"label": str(label), "ok": False, "reason": "label not visible"})
            _hotkey("tab")
            continue
        _hotkey(_MOD, "a")
        _hotkey("delete")
        _type_text(str(val))
        filled += 1
        outcomes.append({"label": str(label), "ok": True, "value": str(val)})
        _hotkey("tab")
        time.sleep(0.2)
    if submit_sel:
        # Try to click a visible submit button, else press Enter.
        if not (isinstance(submit_sel, str) and _click_text(submit_sel)):
            _hotkey("return")
        time.sleep(_SETTLE_SECONDS)
    state = _read_real_page_state()
    extra = " and submitted." if submit_sel else "."
    return _merge_state(
        {"result": f"Filled {filled}/{len(fields)} field(s){extra}", "field_outcomes": outcomes},
        state,
    )


@register("desktopBrowserGoBack")
def browser_go_back(args: Dict[str, Any]) -> Dict[str, Any]:
    _blog("action=go_back")
    _focus_browser()
    _hotkey(_MOD, "[")
    time.sleep(_SETTLE_SECONDS)
    state = _read_real_page_state()
    return _merge_state({"result": "Went back."}, state)


@register("desktopBrowserGoForward")
def browser_go_forward(args: Dict[str, Any]) -> Dict[str, Any]:
    _blog("action=go_forward")
    _focus_browser()
    _hotkey(_MOD, "]")
    time.sleep(_SETTLE_SECONDS)
    state = _read_real_page_state()
    return _merge_state({"result": "Went forward."}, state)


@register("desktopBrowserScroll")
def browser_scroll(args: Dict[str, Any]) -> Dict[str, Any]:
    direction = (args.get("direction") or "down").lower()
    amount = int(args.get("amount", 600))
    _blog("action=scroll dir=%s amount=%d", direction, amount)
    _focus_browser()
    try:
        import pyautogui
        # pyautogui.scroll: positive = up, negative = down.
        pyautogui.scroll(amount if direction == "up" else -amount)
    except Exception as e:  # noqa: BLE001
        raise ToolError(f"Scroll failed: {e}")
    time.sleep(0.5)
    state = _read_real_page_state()
    return _merge_state({"result": f"Scrolled {direction} {amount}px."}, state)


@register("desktopBrowserReadPage")
def browser_read_page(args: Dict[str, Any]) -> Dict[str, Any]:
    """OBSERVE step: return the current URL/title/text of the visible browser."""
    _blog("action=read_page")
    _focus_browser()
    state = _read_real_page_state()
    _blog("verification url=%s title=%s", state.get("url"), state.get("title"))
    return _merge_state({"result": "Current page state."}, state)


def shutdown_browser() -> None:
    """No-op. There is no owned browser process to close.

    Kept so desktop_agent/main.py's lifespan shutdown import continues to work.
    """
    _blog("shutdown_browser: no-op (real browser is user-owned)")
    return None


__all__ = [
    "browser_open",
    "browser_navigate",
    "browser_open_tab",
    "browser_close_tab",
    "browser_search",
    "browser_click",
    "browser_type",
    "browser_fill_form",
    "browser_go_back",
    "browser_go_forward",
    "browser_scroll",
    "browser_read_page",
    "shutdown_browser",
]
