"""
Yashi Desktop Control Agent — Central tool registry.

Each tool module registers handlers into a flat dict `TOOLS` mapping
tool_name -> callable(args: dict) -> dict.

Handlers return a plain dict, typically {"result": "<status string>"}.
Errors should raise ToolError(message) so main.py can map them to {error}.
Shared singletons (Playwright browser/page, confirmation store, etc.) live
on the `State` object so handlers stay stateless and easy to test.
"""

from __future__ import annotations

import importlib
import threading
from typing import Any, Callable, Dict


class ToolError(Exception):
    """Raised by a tool handler to signal a clean, user-facing failure."""

    def __init__(self, message: str, *, fatal: bool = False):
        super().__init__(message)
        self.message = message
        self.fatal = fatal


class State:
    """Process-wide shared state for tool handlers."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.confirmations: Dict[str, Dict[str, Any]] = {}
        self.playwright = None
        self.browser = None
        self.context = None
        self.page = None

    def reset_playwright(self) -> None:
        """Tear down any cached Playwright resources (used on errors)."""
        try:
            if self.page is not None:
                self.page = None
            if self.context is not None:
                self.context = None
            if self.browser is not None:
                self.browser = None
            if self.playwright is not None:
                self.playwright = None
        except Exception:
            pass


STATE = State()

TOOLS: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = {}


def register(name: str):
    """Decorator to register a handler under a tool name."""

    def deco(fn: Callable[[Dict[str, Any]], Dict[str, Any]]):
        TOOLS[name] = fn
        return fn

    return deco


# The set of all tool names Yashi may route to this agent.
# Kept in sync with the functionDeclarations added in server.ts.
DESKTOP_TOOL_NAMES = [
    "openApplication", "closeApplication",
    "openWebsite", "searchWeb", "searchYouTube", "searchGoogle", "searchGitHub",
    "createFile", "readFile", "renameFile", "deleteFile", "moveFile",
    "openFolder", "listFiles", "searchFiles",
    "volumeUp", "volumeDown", "muteToggle", "setVolume",
    "requestPowerAction", "executePowerAction",
    "minimizeWindow", "maximizeWindow", "closeWindow", "switchApplication",
    "copySelected", "pasteClipboard", "getClipboard", "clearClipboard",
    "takeScreenshot", "saveScreenshot", "analyzeScreenshot", "readScreen",
    "desktopBrowserOpen", "desktopBrowserNavigate", "desktopBrowserOpenTab",
    "desktopBrowserCloseTab", "desktopBrowserSearch", "desktopBrowserClick",
    "desktopBrowserType", "desktopBrowserFillForm", "desktopBrowserGoBack",
    "desktopBrowserGoForward", "desktopBrowserScroll",
    "desktopBrowserReadPage",
    "createPythonFile", "runPythonScript", "createProjectFolder", "writeCodeFile",
    "systemInfo", "gpuInfo", "temperatureInfo",
    "brightnessUp", "brightnessDown", "setBrightness",
    "enableAutoStart", "disableAutoStart", "getAutoStartStatus",
    # Wikipedia lookup
    "searchWikipedia", "readWikipedia", "wikipediaSummary",
    # Terminal commands (HIGH-RISK — always requires voice confirmation)
    "terminalCommand", "executeShellCommand",
    # Cybersecurity - Core Recon & Scanning
    "nmapScan", "masscanScan", "nucleiScan", "amassEnum", "subfinderEnum",
    "httpxProbe", "naabuScan", "dnsxQuery", "alterxPermute", "cyberToolCheck",
    # Cybersecurity - Web App Security
    "sqlmapScan", "niktoScan", "gobusterDir", "gobusterDns", "ffufFuzz",
    "dirbScan", "feroxbusterScan", "wafw00fDetect", "whatwebScan",
    "cmsmapScan", "droopescanScan",
    # Cybersecurity - Crypto
    "hashcatCrack", "hashcatBenchmark", "johnCrack",
    "gpgEncrypt", "gpgDecrypt", "gpgSign", "gpgVerify", "gpgKeyGen", "gpgListKeys",
    "opensslHash", "opensslEnc", "opensslGenRSA", "opensslX509",
    "cryptoHash", "cryptoHmac", "cryptoBase64", "cryptoHex", "cryptoRot", "cryptoXor",
    "cyberchefRun", "hashIdentify",
    # Cybersecurity - Reverse Engineering
    "ghidraAnalyze", "r2Analyze", "r2Decompile", "binwalkScan",
    "stringsExtract", "objdumpDisasm", "readelfInfo", "nmSymbols",
    "lddDeps", "fileIdentify", "hexdumpView", "gdbDebug",
    "pwndbgAnalyze", "gefAnalyze", "checksec",
    # Cybersecurity - Forensics
    "volatility3", "volatility2", "yaraScan", "yaraCompile",
    "plasoParse", "plasoExport", "bulkExtractor", "foremostCarve",
    "scalpelCarve", "exiftool", "flsList", "icatExtract", "istatInfo",
    "hashdeep", "ssdeep", "ssdeepCompare", "ewfInfo", "affInfo",
    # Cybersecurity - Network Analysis
    "tsharkCapture", "tsharkAnalyze", "tsharkFollow",
    "tcpdumpCapture", "tcpdumpRead",
    "netstatShow", "ssShow",
    "zeekAnalyze", "zeekLive",
    "iperf3Test", "socatConnect", "ncConnect",
    "iftopShow", "nethogsShow",
    "nmapPing", "arpScan",
    # Cybersecurity - Exploitation
    "msfconsoleRun", "msfExploit", "msfvenomGenerate", "msfvenomList",
    "searchsploit", "searchsploitExploit", "exploitdbSearch", "msfSearch",
    "msfPostModule", "sliverClient", "empireRun", "cobaltStrike",
    "generateShellcode", "generateStager",
    # Cybersecurity - CTF
    "ctfBase64", "ctfBase32", "ctfBase16", "ctfBase85",
    "ctfRot13", "ctfRot47", "ctfCaesar", "ctfAtbash",
    "ctfXor", "ctfXorBrute", "ctfVigenere", "ctfRailFence", "ctfColumnar",
    "ctfHash", "ctfBaseConvert", "ctfUrlEncode", "ctfHtmlEntities", "ctfJwt",
    "ctfFileType", "ctfEntropy", "ctfStrings", "ctfLsb", "ctfQuickDecode",
    # Cybersecurity - Threat Intelligence
    "vtFileScan", "vtUrlScan", "vtGetReport",
    "abuseipdbCheck", "abuseipdbReport",
    "shodanHost", "shodanSearch",
    "otxPulse", "otxSearch", "otxIndicators",
    "greynoiseIp", "greynoiseQuick",
    "urlscanSubmit", "urlscanResult",
    "securitytrailsDomain", "securitytrailsSubdomains",
    "cveSearch", "cveGet",
    "threatfoxQuery", "malwarebazaarQuery", "urlhausQuery",
    "passivetotalQuery", "dnsdbQuery", "intelApiStatus",
    # Cybersecurity - Compliance
    "lynisAudit", "lynisShow", "oscapScan", "oscapInfo", "oscapOval",
    "auditdRules", "ausearchQuery", "kubebenchRun", "kubehunterRun",
    "trivyScan", "checkovScan", "tfsecScan", "cdkDoctor",
    "prowlerScan", "scoutsuiteScan", "c7nRun", "c7nSchema", "complianceCheck",
]

_MODULE_NAMES = [
    "tools_confirmation", "tools_applications", "tools_websites", "tools_search",
    "tools_files", "tools_pc", "tools_windows", "tools_clipboard",
    "tools_screenshot", "tools_browser", "tools_coding", "tools_system",
    "tools_startup", "tools_wikipedia", "tools_security",
    # Cybersecurity modules
    "tools_cyber", "tools_websec", "tools_crypto", "tools_reverse",
    "tools_forensics", "tools_network", "tools_exploit", "tools_ctf",
    "tools_intel", "tools_compliance",
]


def load_all() -> None:
    for mod_name in _MODULE_NAMES:
        importlib.import_module(f".{mod_name}", package="desktop_agent")


__all__ = ["TOOLS", "STATE", "DESKTOP_TOOL_NAMES", "ToolError", "register", "load_all"]
