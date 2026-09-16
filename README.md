<div align="center">
  <h1>⚡ Yashi — Desktop AI Companion & Cybersecurity Co-Pilot</h1>
  <p><strong>Real-Time Duplex Voice · Visual Hologram · Autonomous Desktop Control · Cyber Operations Suite</strong></p>

  <p>
    <img src="https://img.shields.io/badge/Node.js-20%2B-339933?logo=node.js&logoColor=white" alt="Node.js" />
    <img src="https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white" alt="Python" />
    <img src="https://img.shields.io/badge/React-19-61DAFB?logo=react&logoColor=black" alt="React 19" />
    <img src="https://img.shields.io/badge/Electron-43-47848F?logo=electron&logoColor=white" alt="Electron" />
    <img src="https://img.shields.io/badge/AI_Engine-Gemini_Live-8E75B2?logo=google&logoColor=white" alt="Gemini Live" />
    <img src="https://img.shields.io/badge/Security-AES--256--GCM-critical" alt="Security" />
  </p>
</div>

---

## Overview

**Yashi** is an intelligent desktop companion and cybersecurity analyst powered by Google's **Gemini Live API** for ultra-low latency, bidirectional voice streaming and live holographic visual interactions.

It runs locally on your machine as an Electron desktop application paired with a local Python automation engine (`desktop_agent`) featuring **240 tools**. Yashi can see your screen, control desktop applications, inspect system resources, execute shell actions, automate browsers via Playwright, and orchestrate cybersecurity workflows (reconnaissance, web vulnerability analysis, reverse engineering, exploit generation, forensics, and threat intelligence).

---

## Real Working Features

- 🎙️ **Duplex Voice-to-Voice Streaming**: Native Gemini Live WebSocket audio pipeline (`pcm16` @ 24kHz/16kHz) for natural interruptions, live emotional feedback, and high-speed conversational responses.
- 👤 **Holographic Avatar & Animations**: Multi-state visual projection (idle, thinking, speaking) reacting live to conversation state and speech audio dynamics.
- 🖥️ **Vision & Screen Understanding**: Real-time screen capture and analysis to discuss open windows, terminal outputs, browser tabs, or code.
- 🛠️ **240 Desktop Automation Tools**:
  - **Applications & Windows**: Launch, switch, maximize, minimize, or close apps.
  - **Filesystem**: Create, inspect, search, edit, move, or clean files safely.
  - **System Control**: Volume, screen brightness, battery, hardware specs, and power management.
  - **Browser Automation**: Playwright-powered navigation, form filling, clicking, scrolling, and DOM extraction.
  - **Clipboard & Text**: Read, write, and paste clipboard content.
- 🛡️ **Cybersecurity Operations Co-Pilot**:
  - **Reconnaissance**: Nmap, Masscan, Nuclei, Subfinder, Httpx, Amass, Alterx, Naabu.
  - **Web Security**: SQLMap, Nikto, Gobuster, Ffuf, Feroxbuster, Wafw00f, WhatWeb.
  - **Exploitation & C2**: Metasploit search/generation/execution, shellcode generators.
  - **Reverse Engineering & Forensics**: Ghidra, Radare2, GDB, Binwalk, Volatility 3, YARA, ExifTool.
  - **Threat Intelligence**: Shodan, AlienVault OTX, GreyNoise, AbuseIPDB, URLScan, CVE search.
  - **Cryptography & CTF**: Hash identification/cracking, multi-cipher decoding (Base64/32/85, Caesar, ROT, Vigenère, XOR), JWT analysis.
- 🔒 **Encrypted Local Secrets Vault**: Machine-derived AES-256-GCM encrypted storage for user API keys. Keys are never committed, never hardcoded, and never exposed to the frontend.
- 🧠 **Persistent Context & Memory Core**: Long-term recollections of user identity, preferences, and projects with dynamic memory consolidation.
- ⚡ **Multi-Provider Fallback**: Support for text tasks with fallback providers (Gemini, NVIDIA Nemotron, Groq, OpenRouter).

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           Yashi Desktop Shell                           │
│  Electron (electron/main.cjs)                                           │
│  ├─ Spawns bundled Node backend silently (dist/server.cjs)              │
│  └─ Renders UI in borderless / hiddenInset native window                │
│                                                                         │
│  Node Backend & Orchestration (server.ts / dist/server.cjs)             │
│  ├─ Serves React 19 Frontend (Vite in dev, static dist/ in prod)        │
│  ├─ Duplex WebSocket (/live) → Google Gemini Live API                   │
│  ├─ Routes desktop & cyber tools to Python agent on http://127.0.0.1:8765│
│  ├─ Manages encrypted vault (secrets.json.enc) and settings.json        │
│  └─ Multi-provider text fallback (Gemini, Groq, OpenRouter, NVIDIA)     │
│                                                                         │
│  Python Desktop Control Agent (desktop_agent/, FastAPI on port 8765)    │
│  ├─ 240 registered system, desktop, and cyber tools                     │
│  ├─ Vision (Pillow, mss, Tesseract OCR)                                 │
│  ├─ Browser Engine (Playwright Chromium)                                │
│  └─ Security & Pentesting Tool Wrappers                                │
└─────────────────────────────────────────────────────────────────────────┘
```

**Local Storage Paths**:
- **Packaged App**:
  - macOS: `~/Library/Application Support/Yashi/`
  - Windows: `%APPDATA%\Yashi\`
- **Development Mode**: Repo root directory (kept excluded in `.gitignore`)

---

## Tech Stack

| Component | Technology |
|---|---|
| **Desktop Shell** | Electron 43, Electron Builder |
| **Frontend** | React 19, TypeScript, Vite 6, Tailwind CSS, Framer Motion, Lucide Icons |
| **Server / Bridge** | Node.js, Express, WebSocket (`ws`), `@google/genai` SDK |
| **Agent / Automation** | Python 3.10+, FastAPI, Uvicorn, Playwright, PyAutoGUI, Psutil |
| **Encryption** | Node `crypto` (AES-256-GCM with machine-derived key derivation) |

---

## Prerequisites

Ensure you have the following installed on your machine:

1. **Node.js**: Version 20.x or higher — [Download Node.js](https://nodejs.org)
2. **Python**: Version 3.10 or higher — [Download Python](https://python.org)
3. **Google Gemini API Key**: [Get a free API key at Google AI Studio](https://aistudio.google.com/apikey)

### Optional Dependencies

- **Tesseract OCR** (for visual screen reading tools):
  - macOS: `brew install tesseract`
  - Windows: [Tesseract installer for Windows](https://github.com/UB-Mannheim/tesseract/wiki)
- **Playwright Chromium** (for automated browser tasks):
  ```bash
  python3 -m playwright install chromium
  ```
- **External CLI Security Tools** (Nmap, Metasploit, etc.): Only needed if executing specific security commands.

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/vishnukumar001/Yashi.git
cd Yashi
```

### 2. Install Node Dependencies

```bash
npm install
```

### 3. Install Python Agent Dependencies

```bash
npm run agent:install
# (Equivalent to: python3 -m pip install -r desktop_agent/requirements.txt)
```

*(Optional)* Install the Playwright browser engine:
```bash
npm run agent:playwright
```

---

## First-Run Experience & API Key Setup

Yashi is designed to be completely secure and zero-config out of the box. You do **not** need to edit source code to enter your credentials.

When you launch Yashi for the first time:

```
First Launch
     ↓
Welcome to Yashi: Enter your Name or Callsign
     ↓
Enter your Google Gemini API Key
     ↓
Instant Verification & Encrypted Local Storage
     ↓
Yashi Launches Ready for Voice & Control
```

1. **Enter Your Name**: Enter what Yashi should call you (e.g., your name or callsign). Yashi immediately personalizes her speech, greetings, and system instructions for you.
2. **Enter Your Gemini API Key**: Paste your Gemini key from [Google AI Studio](https://aistudio.google.com/apikey).
3. **Automatic Verification**: The backend validates the key live against Google GenAI models. Once verified, it is encrypted via **AES-256-GCM** using a machine-derived key unique to your system and written to `secrets.json.enc`.
4. **Zero Secret Leakage**: The key is never returned to the frontend, never committed to Git, and never shared.

> ⚠️ **Important Security Notice**: Never share your API key or commit `.env` or `secrets.json*` files to any public repository.

---

## Running Yashi

### macOS All-in-One Launcher

```bash
chmod +x start-yashi.sh
./start-yashi.sh
```

This cleans any stale ports, checks dependencies, launches the Python desktop agent on port 8765, boots the Node server on port 3000, and opens your browser.

### Windows All-in-One Launcher

Double-click `start-yashi.bat` or run in Command Prompt:

```cmd
start-yashi.bat
```

### Running in Full Electron Desktop App

To run inside the native Electron desktop shell:

```bash
npm run app
```

### Running Manually (Two Terminals)

If you prefer to run the services separately during development:

```bash
# Terminal 1: Desktop Control Agent
python3 -m uvicorn desktop_agent.main:app --host 127.0.0.1 --port 8765

# Terminal 2: Node Backend & React UI
npm run dev
```

Navigate to `http://localhost:3000` in your browser.

---

## Project Structure

```
yashi/
├── assets/                    # Avatar video states (idle, thinking, talking)
├── build/                     # Application icons (icon.icns, icon.png)
├── cyber_kb/                  # Cybersecurity knowledge base reference sheets
├── desktop_agent/             # Python FastAPI automation agent (240 tools)
│   ├── main.py                # FastAPI entrypoint & /execute router
│   ├── registry.py            # Tool registration decorator and loader
│   ├── tools_applications.py  # App launching and management
│   ├── tools_browser.py       # Playwright browser automation
│   ├── tools_cyber.py         # Recon, nmap, exploit tool integrations
│   ├── tools_files.py         # File operations
│   ├── tools_screenshot.py    # Desktop screenshots & OCR
│   └── requirements.txt       # Python dependencies
├── electron/                  # Electron main process & desktop integration
│   ├── main.cjs               # Main process (window management, process lifecycle)
│   ├── preload.cjs            # Secure contextBridge API
│   └── splash.html            # Startup splash window
├── src/                       # React 19 frontend
│   ├── App.tsx                # Main UI layout and live controls
│   ├── components/
│   │   ├── ApiKeyGate.tsx     # First-run setup modal (Name + Gemini API Key)
│   │   ├── YashiCoreVisualizer.tsx # Holographic living avatar canvas
│   │   ├── SettingsPanel.tsx  # Preferences, mic selection, wake word, agent health
│   │   ├── MemoryDashboard.tsx# Recollections viewer and editor
│   │   └── BrowserAgent.tsx   # Live embedded browser automation view
│   └── lib/                   # Audio session, wake word detection, settings store
├── server.ts                  # Node.js backend (Express + WebSocket + Gemini Live)
├── server_memory.ts           # Long-term persistent memory consolidation
├── server_paths.ts            # Encrypted secrets store & per-user paths
├── electron-builder.yml       # Desktop app packaging configuration
├── start-yashi.sh             # macOS dev launcher script
├── start-yashi.bat            # Windows dev launcher script
├── package.json               # Scripts and dependencies
└── tsconfig.json              # TypeScript configuration
```

---

## Development & Build Commands

| Command | Description |
|---|---|
| `npm run dev` | Start development server with hot module replacement |
| `npm run lint` | Run TypeScript type checking (`tsc --noEmit`) |
| `npm run build` | Build the Vite frontend and bundle `server.ts` to `dist/server.cjs` |
| `npm run app` | Compile and launch inside native Electron shell |
| `npm run dist` | Package the desktop application for your platform |
| `npm run dist:arm` | Package macOS application for Apple Silicon (`arm64`) |
| `npm run agent:install` | Install Python agent requirements |
| `npm run agent:build` | Freeze Python agent into binary bundle via PyInstaller |

---

## Configuration & Environment Variables

While Yashi provides a seamless GUI setup for user configuration, you can optionally supply environment variables in a `.env` file (copied from `.env.example`):

| Variable | Description |
|---|---|
| `GEMINI_API_KEY` | Google Gemini API key (alternative to GUI onboarding) |
| `USER_NAME` | Preferred user name/callsign |
| `AI_PROVIDER` | Preferred text model provider (`gemini`, `nvidia`, `groq`, `openrouter`) |
| `GROQ_API_KEY` | Optional Groq key for text reasoning |
| `OPENROUTER_API_KEY` | Optional OpenRouter key |
| `NVIDIA_API_KEY` | Optional NVIDIA Nemotron key |
| `YASHI_DEBUG` | Set to `1` to enable verbose WebSocket and pipeline logging |

---

## Troubleshooting

| Symptom | Cause | Solution |
|---|---|---|
| **"Desktop Agent Offline"** | Agent process not started | Start it with `python3 -m uvicorn desktop_agent.main:app --host 127.0.0.1 --port 8765` or use `./start-yashi.sh` / `start-yashi.bat`. |
| **Microphone not capturing** | Missing OS permission | **macOS**: System Settings → Privacy & Security → Microphone → Enable Terminal/Yashi. **Windows**: Settings → Privacy → Microphone. |
| **Screen Vision is black** | Missing screen recording permission | **macOS**: System Settings → Privacy & Security → Screen Recording → Enable Yashi/Terminal. |
| **OCR / Screen Read fails** | Tesseract engine not installed | Install Tesseract: macOS (`brew install tesseract`), Windows ([installer link](https://github.com/UB-Mannheim/tesseract/wiki)). |
| **Port 3000 or 8765 in use** | Stale background process | Run `./start-yashi.sh` (auto-cleans stale ports) or `lsof -ti :3000,8765 \| xargs kill -9`. |
| **macOS "App is damaged"** | Gatekeeper quarantine on ad-hoc build | Run `xattr -cr "/Applications/Yashi.app"` to clear quarantine flag. |

---

## Platform Limitations

- **macOS & Windows**: Full desktop control, application switching, volume, brightness, screenshots, and system info supported.
- **Linux**: Core web UI, audio streaming, and cyber tools work. Some platform-specific UI management tools (e.g. brightness or proprietary window managers) may degrade gracefully.
- **Microphone Access**: Real-time voice requires an active microphone connection and permissions in browser/Electron.

---

## License

This project requires a formal license decision by the repository owner (e.g., MIT, Apache 2.0, or Proprietary). All rights reserved by default until designated.
