/* ===========================================================================
 * Yashi — Electron main process
 * ---------------------------------------------------------------------------
 * Responsibilities:
 *   1. Enforce a single running instance.
 *   2. Launch the existing Node backend (server.ts, bundled to dist/server.cjs)
 *      silently as a child process — no terminal window, no browser tab.
 *   3. Show a splash window while the backend boots, then load the real UI
 *      (http://localhost:3000) into the main application window.
 *   4. Clean up the backend (and its child Python agent) on quit.
 *
 * The backend and AI logic are reused verbatim — nothing here reimplements
 * chat/memory/voice.
 * ========================================================================= */

'use strict';

const { app, BrowserWindow, Menu, shell, dialog, session, systemPreferences } = require('electron');
const path = require('path');
const http = require('http');
const { spawn, exec } = require('child_process');
const fs = require('fs');
const crypto = require('crypto');

// --- Constants -------------------------------------------------------------
const SERVER_PORT = 3000;
const SERVER_ORIGIN = `http://localhost:${SERVER_PORT}`;
const SERVER_READY_TIMEOUT_MS = 40_000;

/**
 * Generate a secure random token for desktop agent authentication.
 * This token is generated once per app session and shared between
 * the Node backend and Python agent via environment variables.
 */
function generateAgentToken() {
  return crypto.randomBytes(32).toString('hex');
}

// In development we run from the repo root; when packaged the app files live in
// resources/app (kept asar-unpacked so on-disk path resolution matches dev).
const APP_ROOT = app.isPackaged
  ? path.join(process.resourcesPath, 'app')
  : path.join(__dirname, '..');

const SERVER_ENTRY = path.join(APP_ROOT, 'dist', 'server.cjs');

/** @type {import('child_process').ChildProcess | null} */
let serverProcess = null;
/** @type {BrowserWindow | null} */
let mainWindow = null;
/** @type {BrowserWindow | null} */
let splashWindow = null;
let isQuitting = false;

// ---------------------------------------------------------------------------
// Single-instance guard — second launches focus the existing window instead of
// starting a second backend on the same port.
// ---------------------------------------------------------------------------
const gotSingleInstanceLock = app.requestSingleInstanceLock();
if (!gotSingleInstanceLock) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.show();
      mainWindow.focus();
    }
  });
  app.whenReady().then(bootstrap);
}

// ---------------------------------------------------------------------------
// Resolve the frozen Python desktop agent for the current platform.
//   Windows : agent_dir/yashi-agent.exe
//   macOS   : agent_dir/yashi-agent/yashi-agent (directory bundle)
//   macOS   : agent_dir/yashi-agent          (directory-based .app bundle)
// ---------------------------------------------------------------------------

/**
 * On macOS the frozen agent is a PyInstaller onedir bundle laid out as
 *   agent/yashi-agent/yashi-agent   (the Mach-O executable)
 *   agent/yashi-agent/_internal/    (libs)
 * so we point at the executable inside the bundle directory.
 */
function resolveAgentExecutable() {
  const base = app.isPackaged
    ? path.join(process.resourcesPath, 'agent')
    : path.join(APP_ROOT, 'agent_dist');

  if (process.platform === 'win32') {
    return path.join(base, 'yashi-agent', 'yashi-agent.exe');
  }
  // macOS / Linux: directory-style bundle with the same name inside.
  return path.join(base, 'yashi-agent', 'yashi-agent');
}

// ---------------------------------------------------------------------------
// Backend lifecycle
// ---------------------------------------------------------------------------
function startBackend() {
  if (!fs.existsSync(SERVER_ENTRY)) {
    throw new Error(
      `Backend bundle not found at ${SERVER_ENTRY}. Run "npm run build" first.`,
    );
  }

  // Use the Node runtime bundled with Electron (ELECTRON_RUN_AS_NODE) so the
  // machine does not need a separate Node install once packaged.
  // Data (memories, settings, secrets, logs) must live in a writable per-user
  // folder — on macOS that is ~/Library/Application Support/Yashi.
  const dataDir = app.getPath('userData');

  // Frozen Python desktop agent (bundled as an extraResource when packaged).
  // In development this file won't exist, so the backend falls back to running
  // the agent from source with a local Python interpreter.
  const agentExe = resolveAgentExecutable();

  // Generate a secure token for desktop agent authentication (Node ↔ Python)
  const agentToken = generateAgentToken();

  const env = {
    ...process.env,
    NODE_ENV: 'production',
    ELECTRON_RUN_AS_NODE: '1',
    YASHI_LAUNCHED_BY: 'electron',
    YASHI_DATA_DIR: dataDir,
    YASHI_APP_ROOT: APP_ROOT,
    YASHI_AGENT_TOKEN: agentToken,
  };
  if (fs.existsSync(agentExe)) {
    env.YASHI_AGENT_EXE = agentExe;
  }

  serverProcess = spawn(process.execPath, [SERVER_ENTRY], {
    cwd: APP_ROOT,
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
  });

  process.stdout?.on?.('error', () => {});
  process.stderr?.on?.('error', () => {});

  serverProcess.stdout?.on('data', (d) => {
    try {
      process.stdout.write(`[server] ${d}`);
    } catch {}
  });
  serverProcess.stderr?.on('data', (d) => {
    try {
      process.stderr.write(`[server] ${d}`);
    } catch {}
  });
  serverProcess.on('exit', (code, signal) => {
    if (!isQuitting) {
      dialog.showErrorBox(
        'Yashi backend stopped',
        `The Yashi backend process exited unexpectedly (code ${code}, signal ${signal}).`,
      );
      app.quit();
    }
  });
}

/**
 * Tear down the backend and any descendant processes (the auto-spawned Python
 * agent). Cross-platform: uses `pgrep -P` on macOS/Linux and `taskkill` on
 * Windows so the whole tree is collected.
 */
function killTree(pid) {
  try {
    if (process.platform === 'win32') {
      spawn('taskkill', ['/pid', String(pid), '/T', '/F']);
      return;
    }
    // POSIX: find direct children, recurse, then kill the parent.
    exec(`pgrep -P ${pid}`, (err, stdout) => {
      if (!err && stdout) {
        stdout
          .split('\n')
          .map((s) => s.trim())
          .filter(Boolean)
          .forEach((cpid) => killTree(Number(cpid)));
      }
    });
    try {
      process.kill(pid, 'SIGTERM');
    } catch {
      /* already gone */
    }
  } catch {
    /* best-effort */
  }
}

function stopBackend() {
  if (serverProcess && !serverProcess.killed) {
    killTree(serverProcess.pid);
  }
  serverProcess = null;
}

/** Poll the backend until it answers, or reject on timeout. */
function waitForBackend(timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve, reject) => {
    const tryOnce = () => {
      const req = http.get(SERVER_ORIGIN, (res) => {
        res.resume();
        resolve();
      });
      req.on('error', () => {
        if (Date.now() > deadline) {
          reject(new Error('Backend did not become ready in time.'));
        } else {
          setTimeout(tryOnce, 400);
        }
      });
      req.setTimeout(2000, () => req.destroy());
    };
    tryOnce();
  });
}

// ---------------------------------------------------------------------------
// Windows
// ---------------------------------------------------------------------------
function createSplashWindow() {
  splashWindow = new BrowserWindow({
    width: 420,
    height: 300,
    frame: false,
    transparent: true,
    resizable: false,
    center: true,
    show: true,
    alwaysOnTop: true,
    skipTaskbar: true,
    backgroundColor: '#00000000',
    webPreferences: { contextIsolation: true, nodeIntegration: false },
  });
  splashWindow.loadFile(path.join(__dirname, 'splash.html'));
  splashWindow.on('closed', () => (splashWindow = null));
}

function createMainWindow() {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 800,
    minWidth: 940,
    minHeight: 600,
    show: false, // revealed on ready-to-show to avoid a white flash
    backgroundColor: '#0a0a0f',
    autoHideMenuBar: true,
    title: 'Yashi',
    // The hidden-inset traffic lights look right on a frameless-ish dark UI
    // while keeping standard macOS window controls.
    titleBarStyle: process.platform === 'darwin' ? 'hiddenInset' : 'default',
    webPreferences: {
      preload: path.join(__dirname, 'preload.cjs'),
      contextIsolation: true,
      nodeIntegration: false,
      spellcheck: true,
    },
  });

  Menu.setApplicationMenu(null);

  // Open external links (http/https to non-local hosts) in the real browser
  // instead of navigating the app window.
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith('http') && !url.startsWith(SERVER_ORIGIN)) {
      shell.openExternal(url);
      return { action: 'deny' };
    }
    return { action: 'allow' };
  });

  mainWindow.once('ready-to-show', () => {
    if (splashWindow) splashWindow.close();
    mainWindow?.show();
    mainWindow?.focus();
  }); 

  mainWindow.on('closed', () => (mainWindow = null));

  mainWindow.loadURL(SERVER_ORIGIN);
 
}

// ---------------------------------------------------------------------------
// Bootstrap sequence
// ---------------------------------------------------------------------------
async function bootstrap() {
  app.setAppUserModelId('com.yashi.desktop');

  // Request & configure macOS microphone permissions for voice interactions
  if (process.platform === 'darwin' && systemPreferences && systemPreferences.askForMediaAccess) {
    try {
      const micStatus = systemPreferences.getMediaAccessStatus('microphone');
      if (micStatus !== 'granted') {
        systemPreferences.askForMediaAccess('microphone').catch(() => {});
      }
    } catch (e) {}
  }

  // Authorize audio/media permissions in Electron renderer session
  if (session && session.defaultSession) {
    session.defaultSession.setPermissionRequestHandler((webContents, permission, callback) => {
      const allowed = ['media', 'microphone', 'audioCapture', 'notifications', 'screen'];
      if (allowed.includes(permission)) {
        return callback(true);
      }
      callback(true);
    });

    session.defaultSession.setPermissionCheckHandler((webContents, permission, requestingOrigin) => {
      return true;
    });
  }

  createSplashWindow();

  try {
    console.log("1. Starting backend...");
    startBackend();

    console.log("2. Waiting for backend...");
    await waitForBackend(SERVER_READY_TIMEOUT_MS);

    console.log("3. Backend ready.");

    console.log("4. Creating main window...");
    createMainWindow();

    console.log("5. Main window created.");
  } catch (err) {
    console.error("Bootstrap Error:", err);

    if (splashWindow) splashWindow.close();

    dialog.showErrorBox(
      "Yashi failed to start",
      err instanceof Error ? err.message : String(err)
    );

    app.quit();
  }
}

// ---------------------------------------------------------------------------
// App lifecycle
// ---------------------------------------------------------------------------
app.on('activate', () => {
  // macOS: re-create a window when the dock icon is clicked with none open.
  if (BrowserWindow.getAllWindows().length === 0) createMainWindow();
});

app.on('window-all-closed', () => {
  // On macOS apps stay active until explicitly quit (Cmd+Q).
  if (process.platform !== 'darwin') app.quit();
});

app.on('before-quit', () => {
  isQuitting = true;
  stopBackend();
});

process.on('exit', stopBackend);
