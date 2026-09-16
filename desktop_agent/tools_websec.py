"""
Web Application Security Tools.

Wraps: sqlmap, nikto, gobuster, ffuf, dirb, feroxbuster, wafw00f, whatweb, cmsmap, droopescan.
"""

from __future__ import annotations

import json
import platform
import shlex
import subprocess
import tempfile
from typing import Any, Dict, List, Optional

from .registry import ToolError, register

# Reuse tool finding from tools_cyber
_TOOL_CACHE: Dict[str, Optional[str]] = {}


def _find_tool(name: str) -> Optional[str]:
    if name in _TOOL_CACHE:
        return _TOOL_CACHE[name]

    extra_paths: List[str] = []
    system = platform.system()
    if system == "Darwin":
        extra_paths = ["/opt/homebrew/bin", "/usr/local/bin", "/opt/local/bin"]
    elif system == "Linux":
        extra_paths = ["/usr/local/bin", "/opt/go/bin", os.path.expanduser("~/go/bin")]
    elif system == "Windows":
        extra_paths = [os.path.expanduser("~/go/bin")]

    for path_dir in ["/usr/bin", "/bin"] + extra_paths:
        full = os.path.join(path_dir, name)
        if system == "Windows" and not full.endswith(".exe"):
            full += ".exe"
        if os.path.isfile(full) and os.access(full, os.X_OK):
            _TOOL_CACHE[name] = full
            return full

    try:
        result = subprocess.run(
            ["which", name] if system != "Windows" else ["where", name],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            path = result.stdout.strip().split("\n")[0]
            _TOOL_CACHE[name] = path
            return path
    except Exception:
        pass

    _TOOL_CACHE[name] = None
    return None


def _run_cmd(cmd: List[str], timeout: int = 180, input_data: str = "") -> Dict[str, Any]:
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_data if input_data else None
        )
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
            "command": " ".join(shlex.quote(c) for c in cmd)
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": f"Command timed out after {timeout}s", "command": " ".join(shlex.quote(c) for c in cmd)}
    except Exception as e:
        return {"success": False, "error": str(e), "command": " ".join(shlex.quote(c) for c in cmd)}


def _require_tool(name: str) -> str:
    path = _find_tool(name)
    if not path:
        raise ToolError(f"Tool '{name}' not found. Install it first.")
    return path


# --- SQLMAP ---
@register("sqlmapScan")
def sqlmap_scan(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run sqlmap for SQL injection detection/exploitation.
    Args: url (required), data (POST data), param, method, dbms, technique, risk, level, dump, threads, batch, output_dir
    """
    url = args.get("url")
    if not url:
        raise ToolError("Parameter 'url' is required.")

    sqlmap = _require_tool("sqlmap")
    cmd = [sqlmap, "-u", url, "--batch", "--output-dir", tempfile.gettempdir()]

    if "data" in args:
        cmd.extend(["--data", args["data"]])
    if "param" in args:
        cmd.extend(["-p", args["param"]])
    if "method" in args:
        cmd.extend(["--method", args["method"]])
    if "dbms" in args:
        cmd.extend(["--dbms", args["dbms"]])
    if "technique" in args:
        cmd.extend(["--technique", args["technique"]])
    if "risk" in args:
        cmd.extend(["--risk", str(args["risk"])])
    if "level" in args:
        cmd.extend(["--level", str(args["level"])])
    if args.get("dump", False):
        cmd.append("--dump")
    if args.get("tables", False):
        cmd.append("--tables")
    if args.get("columns", False):
        cmd.append("--columns")
    if "threads" in args:
        cmd.extend(["--threads", str(args["threads"])])

    # Output as JSON if possible
    cmd.extend(["--flush-session", "--fresh-queries"])

    result = _run_cmd(cmd, timeout=600)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    # Parse sqlmap output for key findings
    output = result["stdout"]
    findings = {
        "vulnerable": "sqlmap identified the following injection point" in output.lower() or "parameter" in output.lower() and "vulnerable" in output.lower(),
        "output": output,
        "injection_points": []
    }

    return {"ok": True, "result": findings, "command": result["command"]}


# --- NIKTO ---
@register("niktoScan")
def nikto_scan(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run nikto web server scanner.
    Args: host (required), port, ssl, tuning, plugins, timeout
    """
    host = args.get("host")
    if not host:
        raise ToolError("Parameter 'host' is required.")

    nikto = _require_tool("nikto")
    cmd = [nikto, "-h", host]

    if "port" in args:
        cmd.extend(["-p", str(args["port"])])
    if args.get("ssl", False):
        cmd.append("-ssl")
    if "tuning" in args:
        cmd.extend(["-Tuning", args["tuning"]])
    if "plugins" in args:
        cmd.extend(["-Plugins", args["plugins"]])
    if "timeout" in args:
        cmd.extend(["-timeout", str(args["timeout"])])

    # Format output
    cmd.extend(["-Format", "json", "-output", "-"])

    result = _run_cmd(cmd, timeout=300)

    if not result["success"]:
        # Nikto often returns non-zero even on success, check stderr
        if "ERROR" not in result["stderr"].upper():
            pass  # Might be ok
        else:
            return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    # Parse JSON output
    findings = []
    try:
        # Nikto JSON output
        parsed = json.loads(result["stdout"])
        if isinstance(parsed, dict) and "vulnerabilities" in parsed:
            findings = parsed["vulnerabilities"]
    except Exception:
        # Fallback to text parsing
        findings = [{"raw": line} for line in result["stdout"].split("\n") if "+ " in line]

    return {"ok": True, "result": findings, "count": len(findings), "command": result["command"]}


# --- GOBUSTER ---
@register("gobusterDir")
def gobuster_dir(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run gobuster for directory/file enumeration.
    Args: url (required), wordlist, extensions, threads, status_codes, exclude_status, recursive, wildcard
    """
    url = args.get("url")
    if not url:
        raise ToolError("Parameter 'url' is required.")

    gobuster = _require_tool("gobuster")
    cmd = [gobuster, "dir", "-u", url, "-q"]

    if "wordlist" in args:
        cmd.extend(["-w", args["wordlist"]])
    else:
        # Try common wordlist locations
        for wl in ["/usr/share/wordlists/dirb/common.txt", "/opt/homebrew/share/wordlists/dirb/common.txt", "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt"]:
            if os.path.isfile(wl):
                cmd.extend(["-w", wl])
                break

    if "extensions" in args:
        cmd.extend(["-x", args["extensions"]])
    if "threads" in args:
        cmd.extend(["-t", str(args["threads"])])
    if "status_codes" in args:
        cmd.extend(["-s", args["status_codes"]])
    if "exclude_status" in args:
        cmd.extend(["-b", args["exclude_status"]])
    if args.get("recursive", False):
        cmd.append("-r")
    if args.get("wildcard", False):
        cmd.append("-w")

    cmd.extend(["-o", "-", "-f", "json"])

    result = _run_cmd(cmd, timeout=300)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    findings = []
    for line in result["stdout"].strip().split("\n"):
        if line.strip():
            try:
                findings.append(json.loads(line))
            except Exception:
                pass

    return {"ok": True, "result": findings, "count": len(findings), "command": result["command"]}


@register("gobusterDns")
def gobuster_dns(args: Dict[str, Any]) -> Dict[str, Any]:
    """Run gobuster for DNS subdomain enumeration."""
    domain = args.get("domain")
    if not domain:
        raise ToolError("Parameter 'domain' is required.")

    gobuster = _require_tool("gobuster")
    cmd = [gobuster, "dns", "-d", domain, "-q"]

    if "wordlist" in args:
        cmd.extend(["-w", args["wordlist"]])
    if "threads" in args:
        cmd.extend(["-t", str(args["threads"])])

    cmd.extend(["-o", "-", "-f", "json"])

    result = _run_cmd(cmd, timeout=180)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    findings = []
    for line in result["stdout"].strip().split("\n"):
        if line.strip():
            try:
                findings.append(json.loads(line))
            except Exception:
                pass

    return {"ok": True, "result": findings, "count": len(findings), "command": result["command"]}


# --- FFUF ---
@register("ffufFuzz")
def ffuf_fuzz(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run ffuf for fast web fuzzing.
    Args: url (required, with FUZZ keyword), wordlist, method, headers, data, filters (fc, fl, fw, fs), matchers (mc, ml, mw, ms), rate, threads, recursion
    """
    url = args.get("url")
    if not url:
        raise ToolError("Parameter 'url' is required (must contain FUZZ keyword).")

    ffuf = _require_tool("ffuf")
    cmd = [ffuf, "-u", url, "-s"]

    if "wordlist" in args:
        cmd.extend(["-w", args["wordlist"]])
    else:
        for wl in ["/usr/share/wordlists/dirb/common.txt", "/opt/homebrew/share/wordlists/dirb/common.txt"]:
            if os.path.isfile(wl):
                cmd.extend(["-w", wl])
                break

    if "method" in args:
        cmd.extend(["-X", args["method"]])
    if "headers" in args:
        for h in args["headers"]:
            cmd.extend(["-H", h])
    if "data" in args:
        cmd.extend(["-d", args["data"]])

    # Filters
    for filter_key in ["fc", "fl", "fw", "fs"]:
        if filter_key in args:
            cmd.extend([f"-{filter_key}", str(args[filter_key])])

    # Matchers
    for match_key in ["mc", "ml", "mw", "ms"]:
        if match_key in args:
            cmd.extend([f"-{match_key}", str(args[match_key])])

    if "rate" in args:
        cmd.extend(["-rate", str(args["rate"])])
    if "threads" in args:
        cmd.extend(["-t", str(args["threads"])])
    if args.get("recursion", False):
        cmd.append("-recursion")
    if "recursion_depth" in args:
        cmd.extend(["-recursion-depth", str(args["recursion_depth"])])

    cmd.extend(["-o", "-", "-of", "json"])

    result = _run_cmd(cmd, timeout=300)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    findings = []
    try:
        parsed = json.loads(result["stdout"])
        if isinstance(parsed, dict) and "results" in parsed:
            findings = parsed["results"]
    except Exception:
        pass

    return {"ok": True, "result": findings, "count": len(findings), "command": result["command"]}


# --- DIRB ---
@register("dirbScan")
def dirb_scan(args: Dict[str, Any]) -> Dict[str, Any]:
    """Run dirb for web content scanning."""
    url = args.get("url")
    if not url:
        raise ToolError("Parameter 'url' is required.")

    dirb = _require_tool("dirb")
    cmd = [dirb, url]

    if "wordlist" in args:
        cmd.append(args["wordlist"])
    if "extensions" in args:
        cmd.extend(["-X", args["extensions"]])
    if not args.get("recursive", True):
        cmd.append("-r")

    result = _run_cmd(cmd, timeout=300)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    # Parse text output
    findings = [line.strip() for line in result["stdout"].split("\n") if "CODE:" in line or "==>" in line]

    return {"ok": True, "result": findings, "count": len(findings), "command": result["command"]}


# --- FEROXBUSTER ---
@register("feroxbusterScan")
def feroxbuster_scan(args: Dict[str, Any]) -> Dict[str, Any]:
    """Run feroxbuster for fast recursive content discovery."""
    url = args.get("url")
    if not url:
        raise ToolError("Parameter 'url' is required.")

    feroxbuster = _require_tool("feroxbuster")
    cmd = [feroxbuster, "-u", url, "--json", "--silent"]

    if "wordlist" in args:
        cmd.extend(["-w", args["wordlist"]])
    if "threads" in args:
        cmd.extend(["-t", str(args["threads"])])
    if "depth" in args:
        cmd.extend(["-d", str(args["depth"])])
    if "extensions" in args:
        cmd.extend(["-x", args["extensions"]])
    if args.get("no_recursion", False):
        cmd.append("--no-recursion")

    result = _run_cmd(cmd, timeout=300)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    findings = []
    for line in result["stdout"].strip().split("\n"):
        if line.strip():
            try:
                findings.append(json.loads(line))
            except Exception:
                pass

    return {"ok": True, "result": findings, "count": len(findings), "command": result["command"]}


# --- WAFW00F ---
@register("wafw00fDetect")
def wafw00f_detect(args: Dict[str, Any]) -> Dict[str, Any]:
    """Run wafw00f to detect WAF."""
    url = args.get("url")
    if not url:
        raise ToolError("Parameter 'url' is required.")

    wafw00f = _require_tool("wafw00f")
    cmd = [wafw00f, url, "-j"]

    if "verbose" in args:
        cmd.append("-v")

    result = _run_cmd(cmd, timeout=60)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    try:
        parsed = json.loads(result["stdout"])
    except Exception:
        parsed = {"raw": result["stdout"]}

    return {"ok": True, "result": parsed, "command": result["command"]}


# --- WHATWEB ---
@register("whatwebScan")
def whatweb_scan(args: Dict[str, Any]) -> Dict[str, Any]:
    """Run whatweb for technology fingerprinting."""
    url = args.get("url")
    if not url:
        raise ToolError("Parameter 'url' is required.")

    whatweb = _require_tool("whatweb")
    cmd = [whatweb, "--log-json=-", "--quiet"]

    if "aggression" in args:
        cmd.extend(["-a", str(args["aggression"])])

    cmd.append(url)

    result = _run_cmd(cmd, timeout=60)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    try:
        parsed = json.loads(result["stdout"])
        if isinstance(parsed, list) and parsed:
            parsed = parsed[0]
    except Exception:
        parsed = {"raw": result["stdout"]}

    return {"ok": True, "result": parsed, "command": result["command"]}


# --- CMSMAP ---
@register("cmsmapScan")
def cmsmap_scan(args: Dict[str, Any]) -> Dict[str, Any]:
    """Run CMSmap for CMS detection and vulnerability scanning."""
    url = args.get("url")
    if not url:
        raise ToolError("Parameter 'url' is required.")

    cmsmap = _require_tool("cmsmap")
    cmd = [cmsmap, "-f", "json", "-o", "-"]

    if args.get("force", False):
        cmd.append("-f")
    if args.get("enumerate", False):
        cmd.append("-e")

    cmd.append(url)

    result = _run_cmd(cmd, timeout=180)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    try:
        parsed = json.loads(result["stdout"])
    except Exception:
        parsed = {"raw": result["stdout"]}

    return {"ok": True, "result": parsed, "command": result["command"]}


# --- DROOPESCAN ---
@register("droopescanScan")
def droopescan_scan(args: Dict[str, Any]) -> Dict[str, Any]:
    """Run droopescan for CMS vulnerability scanning (WordPress, Drupal, SilverStripe, Joomla)."""
    cms = args.get("cms")
    url = args.get("url")
    if not cms or not url:
        raise ToolError("Parameters 'cms' and 'url' are required.")

    droopescan = _require_tool("droopescan")
    cmd = [droopescan, "scan", cms, "-u", url, "--output", "json"]

    if "enumerate" in args:
        for e in args["enumerate"]:
            cmd.extend(["--enumerate", e])

    result = _run_cmd(cmd, timeout=180)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    try:
        parsed = json.loads(result["stdout"])
    except Exception:
        parsed = {"raw": result["stdout"]}

    return {"ok": True, "result": parsed, "command": result["command"]}


import os
__all__ = [
    "sqlmap_scan", "nikto_scan", "gobuster_dir", "gobuster_dns",
    "ffuf_fuzz", "dirb_scan", "feroxbuster_scan", "wafw00f_detect",
    "whatweb_scan", "cmsmap_scan", "droopescan_scan"
]