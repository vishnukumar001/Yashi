# Yashi Desktop Control Agent

A local Python FastAPI service that gives Yashi **JARVIS-style desktop control** —
open apps, manage files, control volume, take screenshots, OCR the screen,
automate a real Chromium browser, run code, read system stats, look things up
on Wikipedia, and more.

> **This agent does NOT modify Yashi's UI, personality, or chat system.** It is
> a pure backend tool layer that Yashi's existing Node bridge (`server.ts`)
> calls over HTTP on `127.0.0.1:8765`.

Cross-platform: macOS (Apple Silicon), Windows, and Linux. Volume, window
management, screenshots, OCR, and auto-start use the appropriate native backend
per OS (osascript on macOS, pycaw/win32 on Windows, etc.).

---

## Prerequisites

| Dependency | Why | Notes |
|---|---|---|
| **Python 3.10+** | Runtime | `brew install python@3.12` on macOS |
| **pip** | Install Python packages | Ships with Python |
| **Chromium** (Playwright) | Browser automation | `python3 -m playwright install chromium` |
| **Tesseract OCR** *(optional)* | Screen text reading | `brew install tesseract` on macOS. Non-OCR tools work without it. |

---

## Setup (one-time)

```bash
# 1. Navigate to the project root
cd /path/to/yashi

# 2. Install Python dependencies
python3 -m pip install -r desktop_agent/requirements.txt

# 3. Install the Playwright Chromium browser (one-time, ~130MB download)
python3 -m playwright install chromium

# 4. (Optional) Install Tesseract OCR for screen-reading capabilities
brew install tesseract
```

---

## Run

```bash
# Start the desktop agent on port 8765
python3 -m desktop_agent.main

# Or with uvicorn directly:
python3 -m uvicorn desktop_agent.main:app --host 127.0.0.1 --port 8765
```

The agent binds to `127.0.0.1:8765`. Then start Yashi normally with `npm run dev`
(or `./start-yashi.sh`, which launches both).

---

## API

### `GET /health`
Returns `{ status: "ok", tools: [...], tool_count: N }`.

### `GET /tools`
Returns the list of registered tool names.

### `POST /execute`
```json
{ "tool": "openApplication", "args": { "name": "safari" } }
```
Returns:
```json
{ "ok": true, "result": { "result": "Safari opened." }, "tool": "openApplication" }
```
On error:
```json
{ "ok": false, "error": "File does not exist: ...", "tool": "readFile" }
```

---

## Available Tools (61 total)

### 🖥️ Applications
| Tool | Description |
|---|---|
| `openApplication` | Open Safari, Chrome, VS Code, Calculator, Finder, Terminal, Notes, etc. |
| `closeApplication` | Close a running application by name |

### 🌐 Websites & Search
| Tool | Description |
|---|---|
| `openWebsite` | Open a named site (YouTube, Gmail, GitHub…) or arbitrary URL in the default browser |
| `searchWeb` | Search any engine (Google, YouTube, GitHub, DuckDuckGo, Bing) |
| `searchYouTube` | Shortcut: search YouTube |
| `searchGoogle` | Shortcut: search Google |
| `searchGitHub` | Shortcut: search GitHub |

### 📁 Files
| Tool | Description |
|---|---|
| `createFile` | Create a text file with content |
| `readFile` | Read a file's contents |
| `renameFile` | Rename a file |
| `deleteFile` | Delete a file (sends to Trash by default) |
| `moveFile` | Move a file to a new location |
| `openFolder` | Open Desktop, Documents, Downloads, etc. in Finder |
| `listFiles` | List files in a folder |
| `searchFiles` | Find files by name/extension (e.g. "find my Python files") |

### 🎛️ PC Control
| Tool | Description |
|---|---|
| `volumeUp` | Increase volume (osascript on macOS) |
| `volumeDown` | Decrease volume |
| `setVolume` | Set volume to a specific percentage |
| `muteToggle` | Toggle mute/unmute |
| `brightnessUp` | Increase screen brightness |
| `brightnessDown` | Decrease screen brightness |
| `setBrightness` | Set brightness to an exact level |
| `requestPowerAction` | **Step 1**: Request confirmation token for shutdown/restart/sleep/lock |
| `executePowerAction` | **Step 2**: Execute the power action with a valid token |

### 🪟 Window Management
| Tool | Description |
|---|---|
| `minimizeWindow` | Minimize active or named window |
| `maximizeWindow` | Maximize active or named window |
| `closeWindow` | Close active or named window |
| `switchApplication` | Switch to a named window, or Cmd+Tab cycle |

### 📋 Clipboard
| Tool | Description |
|---|---|
| `copySelected` | Copy selected text (sends Cmd+C, reads clipboard) |
| `pasteClipboard` | Paste text into the active input |
| `getClipboard` | Read current clipboard contents |
| `clearClipboard` | Empty the clipboard |

### 📸 Screenshot & Screen Reading
| Tool | Description |
|---|---|
| `takeScreenshot` | Capture the full screen |
| `saveScreenshot` | Save screenshot to ~/Pictures/YashiScreenshots |
| `analyzeScreenshot` | Screenshot + OCR to extract visible text |
| `readScreen` | Read the active window's title + visible text via OCR |

### 🌐 Browser Automation (Playwright)
| Tool | Description |
|---|---|
| `desktopBrowserOpen` / `desktopBrowserNavigate` | Open a URL in the automation browser |
| `desktopBrowserOpenTab` | Open a new tab |
| `desktopBrowserCloseTab` | Close a tab |
| `desktopBrowserSearch` | Search in the automation browser |
| `desktopBrowserClick` | Click an element by selector or text |
| `desktopBrowserType` | Type text into the active element |
| `desktopBrowserFillForm` | Fill multiple form fields and optionally submit |
| `desktopBrowserGoBack` / `desktopBrowserGoForward` | Navigate history |
| `desktopBrowserScroll` | Scroll the page up or down |

### 💻 Coding Assistance
| Tool | Description |
|---|---|
| `createPythonFile` | Write a .py file |
| `writeCodeFile` | Write a code file in any language |
| `createProjectFolder` | Scaffold a project folder with subfolders |
| `runPythonScript` | Execute a Python script (captured output) |

### 📊 System Information
| Tool | Description |
|---|---|
| `systemInfo` | CPU, RAM, disk usage, uptime |
| `gpuInfo` | NVIDIA GPU utilization, VRAM, temperature (best-effort) |
| `temperatureInfo` | All available temperature sensors |

### 🔁 Auto-start
| Tool | Description |
|---|---|
| `enableAutoStart` | Launch the Yashi agent automatically on macOS login (LaunchAgent) |
| `disableAutoStart` | Remove the auto-start entry |
| `getAutoStartStatus` | Report whether auto-start is enabled |

### 📚 Wikipedia
| Tool | Description |
|---|---|
| `wikipediaSummary` | Quick one-paragraph summary of a topic |
| `searchWikipedia` | Find article titles matching a query |
| `readWikipedia` | Full sectioned text of an article |

---

## Safety

- **Power actions** (shutdown, restart, sleep, lock) require a **two-step confirmation token**: Yashi must first call `requestPowerAction` (which issues a single-use, 60-second token), ask the user out loud to confirm, then call `executePowerAction` with the token. Without a valid token, the action is refused.
- **File deletions** go to the Trash by default (`send2trash`).
- **File operations** are scoped to safe folders (Desktop, Documents, Downloads, Pictures, Music, Videos, home, project root). Paths outside these roots are rejected.
- **Python script execution** has a configurable timeout (default 30s).

---

## Architecture

```
Yashi voice chat (existing, untouched)
        ↓
Gemini Live API (existing)
        ↓
server.ts — functionCall routing
        ↓
HTTP POST → localhost:8765/execute
        ↓
Python FastAPI desktop_agent
        ↓
pyautogui / osascript / psutil / Playwright / pytesseract / Wikipedia-API / etc.
        ↓
macOS Desktop
```
