# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for the Yashi Desktop Control Agent.

Produces a self-contained onedir bundle (yashi-agent/yashi-agent) with an
embedded Python runtime — the target machine needs no Python installed.

Notes:
- registry.load_all() imports the tool modules dynamically (importlib), so each
  must be listed as a hiddenimport or PyInstaller will not bundle it.
- Playwright is intentionally NOT bundled here: its ~300MB Chromium is only used
  by the optional desktopBrowser* tools, whose imports are lazy and degrade
  gracefully. Every other capability works without it.
- console=False → the agent runs with no console window (silent background).
"""

import platform
from PyInstaller.utils.hooks import collect_submodules

hiddenimports = []

# Dynamically-imported agent tool modules (importlib in registry.load_all).
hiddenimports += [
    "desktop_agent",
    "desktop_agent.main",
    "desktop_agent.registry",
    "desktop_agent.tools_confirmation",
    "desktop_agent.tools_applications",
    "desktop_agent.tools_websites",
    "desktop_agent.tools_search",
    "desktop_agent.tools_files",
    "desktop_agent.tools_pc",
    "desktop_agent.tools_windows",
    "desktop_agent.tools_clipboard",
    "desktop_agent.tools_screenshot",
    "desktop_agent.tools_browser",
    "desktop_agent.tools_coding",
    "desktop_agent.tools_system",
    "desktop_agent.tools_startup",
    "desktop_agent.tools_wikipedia",
    "desktop_agent.tools_cyber",
    "desktop_agent.tools_websec",
    "desktop_agent.tools_exploit",
    "desktop_agent.tools_forensics",
    "desktop_agent.tools_network",
    "desktop_agent.tools_reverse",
    "desktop_agent.tools_security",
    "desktop_agent.tools_compliance",
    "desktop_agent.tools_crypto",
    "desktop_agent.tools_ctf",
    "desktop_agent.tools_intel",
]

# Web stack — uvicorn pulls its loop/protocol/lifespan submodules dynamically.
hiddenimports += collect_submodules("uvicorn")
hiddenimports += ["anyio", "click", "h11", "fastapi", "starlette", "pydantic"]

# Cross-platform automation / audio / screen libraries.
if platform.system() == "Windows":
    # Windows-only: pycaw, comtypes, pywin32
    hiddenimports += collect_submodules("pycaw")
    hiddenimports += [
        "comtypes",
        "comtypes.stream",
        "win32api",
        "win32con",
        "win32gui",
        "win32process",
        "win32timezone",
        "pythoncom",
        "pywintypes",
    ]

# Common cross-platform packages (macOS + Windows + Linux)
hiddenimports += [
    "pyautogui",
    "pygetwindow",
    "pyperclip",
    "psutil",
    "PIL",
    "PIL.Image",
]

# Optional (graceful if unavailable at runtime).
for opt in ("pytesseract", "send2trash", "nvidia_ml_py3", "pynvml", "wikipediaapi"):
    try:
        hiddenimports.append(opt)
    except Exception:
        pass

a = Analysis(
    ["run_agent.py"],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "playwright",
        "tkinter",
        # Headless server — no GUI toolkits. pyautogui's helper libs (mouseinfo,
        # pymsgbox) can pull in Qt bindings, and mixing PyQt5+PyQt6 aborts the
        # build. None are needed at runtime.
        "PyQt5",
        "PyQt6",
        "PySide2",
        "PySide6",
        "matplotlib",
        "IPython",
        "notebook",
        # Heavy scientific / ML stack present in the global env but never used by
        # the agent (confirmed: no desktop_agent module imports these). Excluding
        # them cuts the bundle from ~846MB to well under 100MB. pyscreeze uses
        # cv2/numpy only optionally and falls back cleanly without them.
        "torch",
        "torchvision",
        "torchaudio",
        "cv2",
        "numpy",
        "scipy",
        "pandas",
        "onnxruntime",
        "llvmlite",
        "numba",
        "sympy",
        "sklearn",
        "scikit-learn",
        "tensorflow",
        "transformers",
        "lxml",
    ],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="yashi-agent",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="yashi-agent",
)
