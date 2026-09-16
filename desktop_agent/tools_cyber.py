"""
Cybersecurity Core Recon & Scanning Tools.

Wraps: nmap, masscan, nuclei, amass, subfinder, httpx, naabu, dnsx, alterx.
All tools are external binaries that must be installed on the system.
"""

from __future__ import annotations

import json
import platform
import shlex
import subprocess
import time
from typing import Any, Dict, List, Optional

from .registry import ToolError, register

# Tool availability cache
_TOOL_CACHE: Dict[str, Optional[str]] = {}


def _find_tool(name: str) -> Optional[str]:
    """Find tool in PATH or common install locations."""
    if name in _TOOL_CACHE:
        return _TOOL_CACHE[name]

    # Common install paths per platform
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

    # Check PATH
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


def _run_cmd(cmd: List[str], timeout: int = 120, input_data: str = "") -> Dict[str, Any]:
    """Run command with timeout, return structured result."""
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
        raise ToolError(f"Tool '{name}' not found. Install it first (e.g., 'go install -v github.com/projectdiscovery/{name}/cmd/{name}@latest').")
    return path


# --- NMAP ---
@register("nmapScan")
def nmap_scan(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run nmap scan.
    Args: target (required), ports, scan_type (syn, connect, udp, ping), scripts, timing, output_format (xml, json, normal), fast_scan, top_ports, host_discovery
    """
    target = args.get("target")
    if not target:
        raise ToolError("Parameter 'target' is required (IP, CIDR, or hostname).")

    nmap = _require_tool("nmap")
    cmd = [nmap]

    # Scan mode presets
    scan_mode = args.get("scan_mode", "default")  # default, fast, quick, full, vuln

    if scan_mode == "fast":
        # Fast: top 1000 ports, no version detection, no scripts
        cmd.extend(["-F", "-T4"])
    elif scan_mode == "quick":
        # Quick: top 100 ports, no ping
        cmd.extend(["--top-ports", "100", "-T4", "-Pn"])
    elif scan_mode == "full":
        # Full: all ports, version detection, default scripts
        cmd.extend(["-p-", "-sV", "-sC", "-T4"])
    elif scan_mode == "vuln":
        # Vuln scan: vuln scripts, version detection
        cmd.extend(["-sV", "--script", "vuln", "-T4"])
    else:
        # Default (original behavior)
        scan_type = args.get("scan_type", "syn").lower()
        if scan_type == "syn":
            cmd.append("-sS")
        elif scan_type == "connect":
            cmd.append("-sT")
        elif scan_type == "udp":
            cmd.append("-sU")
        elif scan_type == "ping":
            cmd.append("-sn")

        # Ports - default to top 1000 instead of all 65535
        if "ports" in args:
            cmd.extend(["-p", str(args["ports"])])
        elif args.get("top_ports"):
            cmd.extend(["--top-ports", str(args["top_ports"])])
        elif args.get("fast_scan", False):
            cmd.append("-F")  # Top 100 ports
        else:
            cmd.append("--top-ports 1000")  # Default: top 1000 instead of -p-

        # Timing
        timing = args.get("timing", 4)
        cmd.extend(["-T", str(timing)])

        # Host discovery
        if args.get("no_ping", False):
            cmd.append("-Pn")
        if args.get("disable_arp_ping", False):
            cmd.append("--disable-arp-ping")

    # Version detection (unless fast/quick mode)
    if args.get("version", False) and scan_mode not in ["fast", "quick"]:
        cmd.append("-sV")

    # OS detection
    if args.get("os", False):
        cmd.append("-O")

    # Default scripts
    if args.get("default_scripts", False) and scan_mode not in ["fast", "quick"]:
        cmd.append("-sC")

    # Custom scripts
    if "scripts" in args:
        cmd.extend(["--script", args["scripts"]])

    # Script args
    if "script_args" in args:
        cmd.extend(["--script-args", args["script_args"]])

    # Output format
    output_format = args.get("output_format", "json")
    if output_format == "xml":
        cmd.extend(["-oX", "-"])
    elif output_format == "json":
        cmd.extend(["-oJ", "-"])
    else:
        cmd.extend(["-oN", "-"])

    # Min rate / max rate for speed control
    if "min_rate" in args:
        cmd.extend(["--min-rate", str(args["min_rate"])])
    if "max_rate" in args:
        cmd.extend(["--max-rate", str(args["max_rate"])])

    # Parallelism
    if "min_parallelism" in args:
        cmd.extend(["--min-parallelism", str(args["min_parallelism"])])
    if "max_parallelism" in args:
        cmd.extend(["--max-parallelism", str(args["max_parallelism"])])

    # Host timeout
    if "host_timeout" in args:
        cmd.extend(["--host-timeout", args["host_timeout"]])

    cmd.append(target)

    # Dynamic timeout based on scan mode
    timeout_map = {"fast": 60, "quick": 30, "full": 600, "vuln": 600, "default": 300}
    timeout = args.get("timeout", timeout_map.get(scan_mode, 300))

    result = _run_cmd(cmd, timeout=timeout)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    # Parse JSON output if requested
    parsed = None
    if output_format == "json" and result["stdout"]:
        try:
            # nmap JSON output is line-delimited
            lines = result["stdout"].strip().split("\n")
            parsed = [json.loads(line) for line in lines if line.strip()]
        except Exception:
            parsed = result["stdout"]

    return {
        "ok": True,
        "result": parsed or result["stdout"],
        "format": output_format,
        "command": result["command"]
    }


# --- MASSCAN ---
@register("masscanScan")
def masscan_scan(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run masscan for fast port scanning.
    Args: target (required), ports, rate (packets/sec), output_format (json, list)
    """
    target = args.get("target")
    if not target:
        raise ToolError("Parameter 'target' is required.")

    masscan = _require_tool("masscan")
    cmd = [masscan]

    if "ports" in args:
        cmd.extend(["-p", str(args["ports"])])
    else:
        cmd.extend(["-p1-65535"])

    rate = args.get("rate", 1000)
    cmd.extend(["--rate", str(rate)])

    output_format = args.get("output_format", "json")
    if output_format == "json":
        cmd.extend(["-oJ", "-"])
    else:
        cmd.extend(["-oL", "-"])

    cmd.append(target)

    result = _run_cmd(cmd, timeout=300)
    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    parsed = None
    if output_format == "json" and result["stdout"]:
        try:
            parsed = json.loads(result["stdout"])
        except Exception:
            parsed = result["stdout"]

    return {"ok": True, "result": parsed or result["stdout"], "command": result["command"]}


# --- NUCLEI ---
@register("nucleiScan")
def nuclei_scan(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run nuclei vulnerability scanner.
    Args: target (required), templates (path or tags), severity (critical,high,medium,low,info), rate_limit, tags, exclude_tags
    """
    target = args.get("target")
    if not target:
        raise ToolError("Parameter 'target' is required.")

    nuclei = _require_tool("nuclei")
    cmd = [nuclei, "-u", target]

    if "templates" in args:
        cmd.extend(["-t", args["templates"]])
    if "severity" in args:
        cmd.extend(["-severity", args["severity"]])
    if "tags" in args:
        cmd.extend(["-tags", args["tags"]])
    if "exclude_tags" in args:
        cmd.extend(["-exclude-tags", args["exclude_tags"]])
    if "rate_limit" in args:
        cmd.extend(["-rate-limit", str(args["rate_limit"])])

    cmd.extend(["-json", "-silent"])

    result = _run_cmd(cmd, timeout=300)
    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    # Parse line-delimited JSON
    findings = []
    for line in result["stdout"].strip().split("\n"):
        if line.strip():
            try:
                findings.append(json.loads(line))
            except Exception:
                pass

    return {"ok": True, "result": findings, "count": len(findings), "command": result["command"]}


# --- AMASS ---
@register("amassEnum")
def amass_enum(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run Amass for subdomain enumeration.
    Args: domain (required), passive (bool), active (bool), brute (bool), sources, timeout (minutes)
    """
    domain = args.get("domain")
    if not domain:
        raise ToolError("Parameter 'domain' is required.")

    amass = _require_tool("amass")
    cmd = [amass, "enum", "-d", domain, "-json", "-o", "-"]

    if args.get("passive", True):
        cmd.append("-passive")
    if args.get("active", False):
        cmd.append("-active")
    if args.get("brute", False):
        cmd.append("-brute")
    if "sources" in args:
        cmd.extend(["-src", args["sources"]])

    timeout_min = args.get("timeout", 10)
    result = _run_cmd(cmd, timeout=timeout_min * 60)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    # Parse line-delimited JSON
    subdomains = []
    for line in result["stdout"].strip().split("\n"):
        if line.strip():
            try:
                subdomains.append(json.loads(line))
            except Exception:
                pass

    return {"ok": True, "result": subdomains, "count": len(subdomains), "command": result["command"]}


# --- SUBFINDER ---
@register("subfinderEnum")
def subfinder_enum(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run subfinder for fast subdomain enumeration.
    Args: domain (required), sources, recursive, silent
    """
    domain = args.get("domain")
    if not domain:
        raise ToolError("Parameter 'domain' is required.")

    subfinder = _require_tool("subfinder")
    cmd = [subfinder, "-d", domain, "-json", "-silent"]

    if "sources" in args:
        cmd.extend(["-sources", args["sources"]])
    if args.get("recursive", False):
        cmd.append("-recursive")

    result = _run_cmd(cmd, timeout=120)
    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    subdomains = []
    for line in result["stdout"].strip().split("\n"):
        if line.strip():
            try:
                subdomains.append(json.loads(line))
            except Exception:
                pass

    return {"ok": True, "result": subdomains, "count": len(subdomains), "command": result["command"]}


# --- HTTPX ---
@register("httpxProbe")
def httpx_probe(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run httpx to probe HTTP services.
    Args: targets (list or file), ports, paths, status_code, title, tech_detect, json_output
    """
    targets = args.get("targets")
    if not targets:
        raise ToolError("Parameter 'targets' is required (list of URLs/hosts or file path).")

    httpx = _require_tool("httpx")
    cmd = [httpx, "-json", "-silent"]

    if isinstance(targets, list):
        # Write to temp file
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(targets))
            targets_file = f.name
        cmd.extend(["-l", targets_file])
    else:
        cmd.extend(["-l", targets])

    if "ports" in args:
        cmd.extend(["-ports", args["ports"]])
    if "paths" in args:
        cmd.extend(["-path", args["paths"]])
    if args.get("status_code", True):
        cmd.append("-sc")
    if args.get("title", True):
        cmd.append("-title")
    if args.get("tech_detect", True):
        cmd.append("-td")
    if args.get("content_length", True):
        cmd.append("-cl")

    result = _run_cmd(cmd, timeout=120)
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


# --- NAABU ---
@register("naabuScan")
def naabu_scan(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run naabu for fast port scanning.
    Args: host (required), ports, top_ports, rate, json_output
    """
    host = args.get("host")
    if not host:
        raise ToolError("Parameter 'host' is required.")

    naabu = _require_tool("naabu")
    cmd = [naabu, "-host", host, "-json", "-silent"]

    if "ports" in args:
        cmd.extend(["-p", args["ports"]])
    if "top_ports" in args:
        cmd.extend(["-top-ports", str(args["top_ports"])])
    if "rate" in args:
        cmd.extend(["-rate", str(args["rate"])])

    result = _run_cmd(cmd, timeout=120)
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


# --- DNSX ---
@register("dnsxQuery")
def dnsx_query(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run dnsx for DNS reconnaissance.
    Args: domain (required), record_types (A,AAAA,CNAME,MX,TXT,NS,SOA), resolvers, wildcard_filter
    """
    domain = args.get("domain")
    if not domain:
        raise ToolError("Parameter 'domain' is required.")

    dnsx = _require_tool("dnsx")
    cmd = [dnsx, "-json", "-silent"]

    # Input
    cmd.extend(["-d", domain])

    if "record_types" in args:
        cmd.extend(["-retry", "3"])
        for rt in args["record_types"]:
            cmd.extend(["-t", rt])
    else:
        cmd.extend(["-t", "A", "-t", "AAAA", "-t", "CNAME", "-t", "MX", "-t", "TXT", "-t", "NS"])

    if "resolvers" in args:
        cmd.extend(["-r", args["resolvers"]])
    if args.get("wildcard_filter", True):
        cmd.append("-wd")

    result = _run_cmd(cmd, timeout=60)
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


# --- ALTERX ---
@register("alterxPermute")
def alterx_permute(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run alterx for subdomain permutation/alteration.
    Args: domain (required), wordlist, patterns, enum (enable enumeration)
    """
    domain = args.get("domain")
    if not domain:
        raise ToolError("Parameter 'domain' is required.")

    alterx = _require_tool("alterx")
    cmd = [alterx, "-silent"]

    cmd.extend(["-d", domain])

    if "wordlist" in args:
        cmd.extend(["-w", args["wordlist"]])
    if "patterns" in args:
        cmd.extend(["-p", args["patterns"]])
    if args.get("enum", False):
        cmd.append("-enrich")

    result = _run_cmd(cmd, timeout=60)
    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    permutations = [line.strip() for line in result["stdout"].strip().split("\n") if line.strip()]
    return {"ok": True, "result": permutations, "count": len(permutations), "command": result["command"]}


# --- TOOL CHECK ---
@register("cyberToolCheck")
def cyber_tool_check(args: Dict[str, Any]) -> Dict[str, Any]:
    """Check which cybersecurity tools are installed."""
    tools = [
        "nmap", "masscan", "nuclei", "amass", "subfinder",
        "httpx", "naabu", "dnsx", "alterx",
        "sqlmap", "nikto", "gobuster", "ffuf", "dirb",
        "hashcat", "john", "gpg", "openssl",
        "ghidra", "radare2", "r2", "binwalk", "strings",
        "volatility", "volatility3", "autopsy", "plaso", "yara",
        "tshark", "tcpdump", "wireshark", "zeek", "netstat", "ss",
        "msfconsole", "searchsploit", "metasploit-framework",
        "cyberchef", "gitleaks", "trufflehog"
    ]

    results = {}
    for tool in tools:
        path = _find_tool(tool)
        results[tool] = {"installed": path is not None, "path": path}

    installed = [t for t, r in results.items() if r["installed"]]
    missing = [t for t, r in results.items() if not r["installed"]]

    return {
        "ok": True,
        "result": {
            "installed_count": len(installed),
            "missing_count": len(missing),
            "installed": installed,
            "missing": missing,
            "details": results
        }
    }


import os
__all__ = [
    "nmap_scan", "masscan_scan", "nuclei_scan", "amass_enum",
    "subfinder_enum", "httpx_probe", "naabu_scan", "dnsx_query",
    "alterx_permute", "cyber_tool_check"
]