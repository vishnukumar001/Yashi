"""
Digital Forensics & Incident Response Tools.

Wraps: volatility/volatility3, autopsy, plaso (log2timeline), yara, bulk_extractor, foremost, scalpel, exiftool, autopsy, sleuthkit, ewftools, afflib, hashdeep, ssdeep, fuzzy hashing.
"""

from __future__ import annotations

import json
import platform
import shlex
import subprocess
import os
import tempfile
from typing import Any, Dict, List, Optional

from .registry import ToolError, register

_TOOL_CACHE: Dict[str, Optional[str]] = {}


def _find_tool(name: str) -> Optional[str]:
    if name in _TOOL_CACHE:
        return _TOOL_CACHE[name]

    extra_paths: List[str] = []
    system = platform.system()
    if system == "Darwin":
        extra_paths = ["/opt/homebrew/bin", "/usr/local/bin", "/opt/local/bin"]
    elif system == "Linux":
        extra_paths = ["/usr/local/bin", "/opt/volatility/vol.py", "/opt/plaso/log2timeline.py"]
    elif system == "Windows":
        extra_paths = [os.path.expanduser("~/volatility/vol.py")]

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


def _run_cmd(cmd: List[str], timeout: int = 300, input_data: str = "") -> Dict[str, Any]:
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


# --- VOLATILITY 3 ---
@register("volatility3")
def volatility3_analyze(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run Volatility 3 memory analysis.
    Args: memory_image (required), plugin (required), output_format (json, text, csv), config, profile
    """
    memory = args.get("memory_image")
    plugin = args.get("plugin")
    if not memory or not os.path.isfile(memory):
        raise ToolError("Parameter 'memory_image' is required and must exist.")
    if not plugin:
        raise ToolError("Parameter 'plugin' is required (e.g., windows.pslist, linux.lsmod).")

    vol = _find_tool("vol") or _find_tool("volatility3") or _find_tool("python3")
    if vol.endswith("python3"):
        # Find vol.py
        vol_script = _find_tool("vol.py")
        if not vol_script:
            raise ToolError("Volatility 3 not found. Install with 'pip install volatility3'.")
        cmd = ["python3", vol_script, "-f", memory, plugin]
    else:
        cmd = [vol, "-f", memory, plugin]

    output_format = args.get("output_format", "json")
    if output_format == "json":
        cmd.extend(["--output", "json"])
    elif output_format == "csv":
        cmd.extend(["--output", "csv"])

    if "config" in args:
        cmd.extend(["-c", args["config"]])

    result = _run_cmd(cmd, timeout=600)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    parsed = None
    if output_format == "json":
        try:
            parsed = json.loads(result["stdout"])
        except Exception:
            parsed = result["stdout"]

    return {"ok": True, "result": parsed or result["stdout"], "command": result["command"]}


@register("volatility2")
def volatility2_analyze(args: Dict[str, Any]) -> Dict[str, Any]:
    """Run Volatility 2 (legacy) memory analysis."""
    memory = args.get("memory_image")
    plugin = args.get("plugin")
    profile = args.get("profile")
    if not memory or not os.path.isfile(memory):
        raise ToolError("Parameter 'memory_image' is required and must exist.")
    if not plugin:
        raise ToolError("Parameter 'plugin' is required.")
    if not profile:
        raise ToolError("Parameter 'profile' is required for Volatility 2.")

    vol = _find_tool("vol.py") or _find_tool("volatility")
    if not vol:
        raise ToolError("Volatility 2 not found.")

    cmd = ["python2", vol, "-f", memory, f"--profile={profile}", plugin]

    if "output_file" in args:
        cmd.extend(["--output-file", args["output_file"]])

    result = _run_cmd(cmd, timeout=600)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    return {"ok": True, "result": result["stdout"], "command": result["command"]}


# --- YARA ---
@register("yaraScan")
def yara_scan(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Scan file/directory with YARA rules.
    Args: target (file or directory), rules (file or directory), recursive, threads, timeout, max_match_data
    """
    target = args.get("target")
    rules = args.get("rules")
    if not target or not os.path.exists(target):
        raise ToolError("Parameter 'target' is required and must exist.")
    if not rules or not os.path.exists(rules):
        raise ToolError("Parameter 'rules' is required and must exist.")

    yara = _require_tool("yara")
    cmd = [yara]

    if args.get("recursive", True) and os.path.isdir(target):
        cmd.append("-r")

    if "threads" in args:
        cmd.extend(["-j", str(args["threads"])])

    if "timeout" in args:
        cmd.extend(["-t", str(args["timeout"])])

    if "max_match_data" in args:
        cmd.extend(["-d", f"max_match_data={args['max_match_data']}"])

    # Output as JSON
    cmd.extend(["-w", "-f", rules, target])

    result = _run_cmd(cmd, timeout=300)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    # Parse YARA output
    matches = []
    for line in result["stdout"].strip().split("\n"):
        if line.strip():
            parts = line.split(" ", 2)
            if len(parts) >= 2:
                matches.append({"rule": parts[0], "file": parts[1], "tags": parts[2] if len(parts) > 2 else ""})

    return {"ok": True, "result": matches, "count": len(matches), "command": result["command"]}


@register("yaraCompile")
def yara_compile(args: Dict[str, Any]) -> Dict[str, Any]:
    """Compile YARA rules for faster scanning."""
    rules = args.get("rules")
    output = args.get("output", "rules.compiled")
    if not rules or not os.path.exists(rules):
        raise ToolError("Parameter 'rules' is required and must exist.")

    yarac = _require_tool("yarac")
    cmd = [yarac, rules, output]

    result = _run_cmd(cmd, timeout=60)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    return {"ok": True, "result": f"Compiled rules written to {output}", "command": result["command"]}


# --- PLASO (log2timeline) ---
@register("plasoParse")
def plaso_parse(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Parse forensic artifacts with Plaso (log2timeline).
    Args: source (file/directory/image), output (plaso storage), parser_filter, hashers
    """
    source = args.get("source")
    output = args.get("output", "timeline.plaso")
    if not source or not os.path.exists(source):
        raise ToolError("Parameter 'source' is required and must exist.")

    log2timeline = _find_tool("log2timeline.py")
    if not log2timeline:
        raise ToolError("Plaso not found. Install with 'pip install plaso'.")

    cmd = ["python3", log2timeline, "--storage-file", output]

    if "parser_filter" in args:
        cmd.extend(["--parsers", args["parser_filter"]])

    if "hashers" in args:
        cmd.extend(["--hashers", args["hashers"]])

    cmd.append(source)

    result = _run_cmd(cmd, timeout=1800)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    return {"ok": True, "result": f"Timeline written to {output}", "command": result["command"]}


@register("plasoExport")
def plaso_export(args: Dict[str, Any]) -> Dict[str, Any]:
    """Export Plaso timeline to various formats."""
    storage = args.get("storage")
    output = args.get("output", "timeline.csv")
    format_type = args.get("format", "csv")
    if not storage or not os.path.isfile(storage):
        raise ToolError("Parameter 'storage' is required and must exist.")

    psort = _find_tool("psort.py")
    if not psort:
        raise ToolError("Plaso psort not found.")

    cmd = ["python3", psort, "-z", "UTC", "-o", format_type, "-w", output, storage]

    if "filter" in args:
        cmd.extend(["--filter", args["filter"]])

    result = _run_cmd(cmd, timeout=300)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    return {"ok": True, "result": f"Exported to {output}", "command": result["command"]}


# --- BULK_EXTRACTOR ---
@register("bulkExtractor")
def bulk_extractor_run(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run bulk_extractor for feature extraction.
    Args: image (required), output_dir, patterns, email, url, domain, wordlist, threads
    """
    image = args.get("image")
    output = args.get("output", "bulk_output")
    if not image or not os.path.exists(image):
        raise ToolError("Parameter 'image' is required and must exist.")

    bulk = _require_tool("bulk_extractor")
    cmd = [bulk, "-o", output]

    if "patterns" in args:
        cmd.extend(["-f", args["patterns"]])
    if args.get("email", True):
        cmd.append("-E")
    if args.get("url", True):
        cmd.append("-U")
    if args.get("domain", True):
        cmd.append("-D")
    if "wordlist" in args:
        cmd.extend(["-w", args["wordlist"]])
    if "threads" in args:
        cmd.extend(["-j", str(args["threads"])])

    cmd.append(image)

    result = _run_cmd(cmd, timeout=1800)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    return {"ok": True, "result": f"Extraction complete in {output}", "command": result["command"]}


# --- FOREMOST / SCALPEL ---
@register("foremostCarve")
def foremost_carve(args: Dict[str, Any]) -> Dict[str, Any]:
    """Carve files with foremost."""
    image = args.get("image")
    output = args.get("output", "foremost_output")
    if not image or not os.path.exists(image):
        raise ToolError("Parameter 'image' is required and must exist.")

    foremost = _require_tool("foremost")
    cmd = [foremost, "-o", output]

    if "config" in args:
        cmd.extend(["-c", args["config"]])
    if "types" in args:
        cmd.extend(["-t", args["types"]])

    cmd.extend(["-v", image])

    result = _run_cmd(cmd, timeout=600)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    return {"ok": True, "result": f"Carved files in {output}", "command": result["command"]}


@register("scalpelCarve")
def scalpel_carve(args: Dict[str, Any]) -> Dict[str, Any]:
    """Carve files with scalpel."""
    image = args.get("image")
    output = args.get("output", "scalpel_output")
    if not image or not os.path.exists(image):
        raise ToolError("Parameter 'image' is required and must exist.")

    scalpel = _require_tool("scalpel")
    cmd = [scalpel, "-o", output]

    if "config" in args:
        cmd.extend(["-c", args["config"]])

    cmd.append(image)

    result = _run_cmd(cmd, timeout=600)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    return {"ok": True, "result": f"Carved files in {output}", "command": result["command"]}


# --- EXIFTOOL ---
@register("exiftool")
def exiftool_extract(args: Dict[str, Any]) -> Dict[str, Any]:
    """Extract metadata with exiftool."""
    file_path = args.get("file_path")
    if not file_path or not os.path.isfile(file_path):
        raise ToolError("Parameter 'file_path' is required and must exist.")

    exiftool = _require_tool("exiftool")
    cmd = [exiftool, "-j"]  # JSON output

    if "tags" in args:
        for tag in args["tags"]:
            cmd.extend(["-" + tag])

    cmd.append(file_path)

    result = _run_cmd(cmd, timeout=60)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    try:
        parsed = json.loads(result["stdout"])
        if parsed:
            parsed = parsed[0]
    except Exception:
        parsed = result["stdout"]

    return {"ok": True, "result": parsed, "command": result["command"]}


# --- SLEUTH KIT ---
@register("flsList")
def fls_list(args: Dict[str, Any]) -> Dict[str, Any]:
    """List files in filesystem image (fls)."""
    image = args.get("image")
    if not image or not os.path.exists(image):
        raise ToolError("Parameter 'image' is required and must exist.")

    fls = _require_tool("fls")
    cmd = [fls]

    if args.get("recursive", True):
        cmd.append("-r")
    if args.get("deleted", False):
        cmd.append("-d")
    if args.get("metadata", False):
        cmd.append("-m")

    if "offset" in args:
        cmd.extend(["-o", str(args["offset"])])
    if "partition" in args:
        cmd.extend(["-p", str(args["partition"])])

    cmd.append(image)

    result = _run_cmd(cmd, timeout=120)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    files = result["stdout"].strip().split("\n")
    return {"ok": True, "result": files, "count": len(files), "command": result["command"]}


@register("icatExtract")
def icat_extract(args: Dict[str, Any]) -> Dict[str, Any]:
    """Extract file by inode (icat)."""
    image = args.get("image")
    inode = args.get("inode")
    output = args.get("output")
    if not image or not os.path.exists(image):
        raise ToolError("Parameter 'image' is required and must exist.")
    if not inode:
        raise ToolError("Parameter 'inode' is required.")
    if not output:
        raise ToolError("Parameter 'output' is required.")

    icat = _require_tool("icat")
    cmd = [icat]

    if "offset" in args:
        cmd.extend(["-o", str(args["offset"])])
    if "partition" in args:
        cmd.extend(["-p", str(args["partition"])])

    cmd.extend([image, str(inode)])

    result = _run_cmd(cmd, timeout=60)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    # Write binary output
    with open(output, "wb") as f:
        f.write(result["stdout"].encode("latin-1"))

    return {"ok": True, "result": f"Extracted inode {inode} to {output}", "command": result["command"]}


@register("istatInfo")
def istat_info(args: Dict[str, Any]) -> Dict[str, Any]:
    """Display inode details (istat)."""
    image = args.get("image")
    inode = args.get("inode")
    if not image or not os.path.exists(image):
        raise ToolError("Parameter 'image' is required and must exist.")
    if not inode:
        raise ToolError("Parameter 'inode' is required.")

    istat = _require_tool("istat")
    cmd = [istat]

    if "offset" in args:
        cmd.extend(["-o", str(args["offset"])])
    if "partition" in args:
        cmd.extend(["-p", str(args["partition"])])

    cmd.extend([image, str(inode)])

    result = _run_cmd(cmd, timeout=30)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    return {"ok": True, "result": result["stdout"], "command": result["command"]}


# --- HASHDEEP / SSDEEP ---
@register("hashdeep")
def hashdeep_hash(args: Dict[str, Any]) -> Dict[str, Any]:
    """Compute recursive hashes with hashdeep."""
    path = args.get("path")
    if not path or not os.path.exists(path):
        raise ToolError("Parameter 'path' is required and must exist.")

    hashdeep = _require_tool("hashdeep")
    cmd = [hashdeep, "-r"]

    if "algorithms" in args:
        cmd.extend(["-c", args["algorithms"]])
    else:
        cmd.extend(["-c", "md5,sha1,sha256"])

    if "output" in args:
        cmd.extend(["-o", args["output"]])

    cmd.append(path)

    result = _run_cmd(cmd, timeout=300)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    return {"ok": True, "result": result["stdout"], "command": result["command"]}


@register("ssdeep")
def ssdeep_fuzzy(args: Dict[str, Any]) -> Dict[str, Any]:
    """Compute fuzzy hashes with ssdeep."""
    path = args.get("path")
    if not path or not os.path.exists(path):
        raise ToolError("Parameter 'path' is required and must exist.")

    ssdeep = _require_tool("ssdeep")
    cmd = [ssdeep, "-r"]

    if "output" in args:
        cmd.extend(["-o", args["output"]])

    cmd.append(path)

    result = _run_cmd(cmd, timeout=300)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    return {"ok": True, "result": result["stdout"], "command": result["command"]}


@register("ssdeepCompare")
def ssdeep_compare(args: Dict[str, Any]) -> Dict[str, Any]:
    """Compare fuzzy hashes."""
    hash1 = args.get("hash1")
    hash2 = args.get("hash2")
    if not hash1 or not hash2:
        raise ToolError("Parameters 'hash1' and 'hash2' are required.")

    ssdeep = _require_tool("ssdeep")
    cmd = [ssdeep, "-c", hash1, hash2]

    result = _run_cmd(cmd, timeout=10)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    return {"ok": True, "result": result["stdout"], "command": result["command"]}


# --- EWFTOOLS / AFFLIB ---
@register("ewfinfo")
def ewf_info(args: Dict[str, Any]) -> Dict[str, Any]:
    """Display EWF image info."""
    image = args.get("image")
    if not image or not os.path.exists(image):
        raise ToolError("Parameter 'image' is required and must exist.")

    ewfinfo = _require_tool("ewfinfo")
    cmd = [ewfinfo, image]

    result = _run_cmd(cmd, timeout=30)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    return {"ok": True, "result": result["stdout"], "command": result["command"]}


@register("affinfo")
def aff_info(args: Dict[str, Any]) -> Dict[str, Any]:
    """Display AFF image info."""
    image = args.get("image")
    if not image or not os.path.exists(image):
        raise ToolError("Parameter 'image' is required and must exist.")

    affinfo = _require_tool("affinfo")
    cmd = [affinfo, image]

    result = _run_cmd(cmd, timeout=30)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    return {"ok": True, "result": result["stdout"], "command": result["command"]}


__all__ = [
    "volatility3_analyze", "volatility2_analyze", "yara_scan", "yara_compile",
    "plaso_parse", "plaso_export", "bulk_extractor_run", "foremost_carve",
    "scalpel_carve", "exiftool_extract", "fls_list", "icat_extract",
    "istat_info", "hashdeep_hash", "ssdeep_fuzzy", "ssdeep_compare",
    "ewf_info", "aff_info"
]