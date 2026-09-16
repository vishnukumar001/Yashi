"""
Reverse Engineering & Binary Analysis Tools.

Wraps: ghidra, radare2 (r2), binwalk, strings, objdump, readelf, nm, ldd, file, xxd, hexdump, gdb, pwndbg, gef.
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
        extra_paths = ["/opt/homebrew/bin", "/usr/local/bin", "/opt/local/bin", "/Applications/Ghidra.app/Contents/Eclipse/ghidraRun"]
    elif system == "Linux":
        extra_paths = ["/usr/local/bin", "/opt/ghidra/ghidraRun", "/opt/radare2/bin"]
    elif system == "Windows":
        extra_paths = [os.path.expanduser("~/ghidra/ghidraRun.bat")]

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


# --- GHIDRA (headless analyzer) ---
@register("ghidraAnalyze")
def ghidra_analyze(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run Ghidra headless analysis on a binary.
    Args: binary_path (required), project_dir, project_name, script_path, script_args, delete_project
    """
    binary = args.get("binary_path")
    if not binary or not os.path.isfile(binary):
        raise ToolError("Parameter 'binary_path' is required and must exist.")

    ghidra = _find_tool("ghidraRun") or _find_tool("analyzeHeadless")
    if not ghidra:
        raise ToolError("Ghidra not found. Install Ghidra and ensure ghidraRun or analyzeHeadless is in PATH.")

    project_dir = args.get("project_dir", tempfile.gettempdir())
    project_name = args.get("project_name", "yashi_ghidra_proj")
    script = args.get("script_path")

    cmd = [ghidra, project_dir, project_name, "-import", binary, "-postScript", script] if script else [ghidra, project_dir, project_name, "-import", binary]

    if "script_args" in args:
        cmd.extend(args["script_args"])

    if args.get("delete_project", True):
        cmd.append("-deleteProject")

    result = _run_cmd(cmd, timeout=600)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    return {"ok": True, "result": result["stdout"], "command": result["command"]}


# --- RADARE2 ---
@register("r2Analyze")
def r2_analyze(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run radare2 analysis on a binary.
    Args: binary_path (required), commands (list of r2 commands), json_output
    """
    binary = args.get("binary_path")
    if not binary or not os.path.isfile(binary):
        raise ToolError("Parameter 'binary_path' is required and must exist.")

    r2 = _require_tool("r2")
    commands = args.get("commands", ["aaa", "aflj", "iej", "ij", "izzj", "pdj @ entry0"])

    cmd_str = ";".join(commands)
    cmd = [r2, "-q", "-c", cmd_str, binary]

    if args.get("json_output", True):
        pass  # commands already use j suffix

    result = _run_cmd(cmd, timeout=180)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    # Parse JSON outputs
    output = result["stdout"]
    findings = {}
    for line in output.split("\n"):
        if line.strip().startswith("{"):
            try:
                parsed = json.loads(line)
                findings.update(parsed)
            except Exception:
                pass

    return {"ok": True, "result": findings or output, "command": result["command"]}


@register("r2Decompile")
def r2_decompile(args: Dict[str, Any]) -> Dict[str, Any]:
    """Decompile function with radare2 (requires r2dec or r2ghidra)."""
    binary = args.get("binary_path")
    function = args.get("function", "main")
    if not binary or not os.path.isfile(binary):
        raise ToolError("Parameter 'binary_path' is required and must exist.")

    r2 = _require_tool("r2")
    cmd = [r2, "-q", "-c", f"aaa; pdg @ {function}", binary]

    result = _run_cmd(cmd, timeout=120)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    return {"ok": True, "result": result["stdout"], "command": result["command"]}


# --- BINWALK ---
@register("binwalkScan")
def binwalk_scan(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run binwalk for firmware/embedded file analysis.
    Args: file_path (required), extract, signature, entropy, recursion_depth
    """
    file_path = args.get("file_path")
    if not file_path or not os.path.isfile(file_path):
        raise ToolError("Parameter 'file_path' is required and must exist.")

    binwalk = _require_tool("binwalk")
    cmd = [binwalk]

    if args.get("extract", False):
        cmd.extend(["-e", "--run-as=root"])
    if args.get("signature", True):
        cmd.append("-B")
    if args.get("entropy", False):
        cmd.append("-E")
    if "recursion_depth" in args:
        cmd.extend(["-d", str(args["recursion_depth"])])

    cmd.extend(["-f", "-q", file_path])  # JSON output

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


# --- STRINGS ---
@register("stringsExtract")
def strings_extract(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract strings from binary.
    Args: file_path (required), min_length, encoding (ascii, unicode, all), offset, limit
    """
    file_path = args.get("file_path")
    if not file_path or not os.path.isfile(file_path):
        raise ToolError("Parameter 'file_path' is required and must exist.")

    strings_cmd = _require_tool("strings")
    cmd = [strings_cmd]

    min_len = args.get("min_length", 4)
    cmd.extend(["-n", str(min_len)])

    encoding = args.get("encoding", "ascii")
    if encoding == "unicode":
        cmd.append("-el")
    elif encoding == "all":
        cmd.append("-a")

    if "offset" in args:
        cmd.extend(["-o", str(args["offset"])])

    cmd.append(file_path)

    result = _run_cmd(cmd, timeout=60)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    strings_list = result["stdout"].strip().split("\n")
    if "limit" in args:
        strings_list = strings_list[:args["limit"]]

    return {"ok": True, "result": strings_list, "count": len(strings_list), "command": result["command"]}


# --- OBJDUMP ---
@register("objdumpDisasm")
def objdump_disasm(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Disassemble binary with objdump.
    Args: file_path (required), architecture, syntax (intel, att), start_address, stop_address, function
    """
    file_path = args.get("file_path")
    if not file_path or not os.path.isfile(file_path):
        raise ToolError("Parameter 'file_path' is required and must exist.")

    objdump = _require_tool("objdump")
    cmd = [objdump, "-d"]

    if "architecture" in args:
        cmd.extend(["-m", args["architecture"]])
    if "syntax" in args:
        cmd.extend(["-M", args["syntax"]])
    if "start_address" in args:
        cmd.extend(["--start-address", args["start_address"]])
    if "stop_address" in args:
        cmd.extend(["--stop-address", args["stop_address"]])

    cmd.append(file_path)

    result = _run_cmd(cmd, timeout=60)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    return {"ok": True, "result": result["stdout"], "command": result["command"]}


# --- READELF ---
@register("readelfInfo")
def readelf_info(args: Dict[str, Any]) -> Dict[str, Any]:
    """Display ELF file information."""
    file_path = args.get("file_path")
    if not file_path or not os.path.isfile(file_path):
        raise ToolError("Parameter 'file_path' is required and must exist.")

    readelf = _require_tool("readelf")
    cmd = [readelf]

    if "headers" in args:
        cmd.append("-h")
    if "sections" in args:
        cmd.append("-S")
    if "segments" in args:
        cmd.append("-l")
    if "symbols" in args:
        cmd.append("-s")
    if "relocations" in args:
        cmd.append("-r")
    if "dynamic" in args:
        cmd.append("-d")
    if "notes" in args:
        cmd.append("-n")
    if "histogram" in args:
        cmd.append("-I")
    if "all" in args:
        cmd.append("-a")

    cmd.append(file_path)

    result = _run_cmd(cmd, timeout=60)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    return {"ok": True, "result": result["stdout"], "command": result["command"]}


# --- NM ---
@register("nmSymbols")
def nm_symbols(args: Dict[str, Any]) -> Dict[str, Any]:
    """List symbols from object file."""
    file_path = args.get("file_path")
    if not file_path or not os.path.isfile(file_path):
        raise ToolError("Parameter 'file_path' is required and must exist.")

    nm = _require_tool("nm")
    cmd = [nm]

    if args.get("defined_only", False):
        cmd.append("-D")
    if args.get("undefined_only", False):
        cmd.append("-u")
    if args.get("dynamic", False):
        cmd.append("-D")
    if args.get("demangle", True):
        cmd.append("-C")

    cmd.append(file_path)

    result = _run_cmd(cmd, timeout=30)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    symbols = result["stdout"].strip().split("\n")
    return {"ok": True, "result": symbols, "count": len(symbols), "command": result["command"]}


# --- LDD ---
@register("lddDeps")
def ldd_deps(args: Dict[str, Any]) -> Dict[str, Any]:
    """List dynamic library dependencies."""
    file_path = args.get("file_path")
    if not file_path or not os.path.isfile(file_path):
        raise ToolError("Parameter 'file_path' is required and must exist.")

    ldd = _require_tool("ldd")
    cmd = [ldd]

    if args.get("verbose", False):
        cmd.append("-v")
    if args.get("unused", False):
        cmd.append("-u")

    cmd.append(file_path)

    result = _run_cmd(cmd, timeout=30)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    deps = result["stdout"].strip().split("\n")
    return {"ok": True, "result": deps, "count": len(deps), "command": result["command"]}


# --- FILE ---
@register("fileIdentify")
def file_identify(args: Dict[str, Any]) -> Dict[str, Any]:
    """Identify file type using libmagic."""
    file_path = args.get("file_path")
    if not file_path or not os.path.isfile(file_path):
        raise ToolError("Parameter 'file_path' is required and must exist.")

    file_cmd = _require_tool("file")
    cmd = [file_cmd]

    if args.get("mime", False):
        cmd.append("--mime-type")
    if args.get("mime_encoding", False):
        cmd.append("--mime-encoding")
    if args.get("brief", False):
        cmd.append("-b")

    cmd.append(file_path)

    result = _run_cmd(cmd, timeout=10)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    return {"ok": True, "result": result["stdout"].strip(), "command": result["command"]}


# --- XXD / HEXDUMP ---
@register("hexdump")
def hexdump_view(args: Dict[str, Any]) -> Dict[str, Any]:
    """Display hex dump of file."""
    file_path = args.get("file_path")
    if not file_path or not os.path.isfile(file_path):
        raise ToolError("Parameter 'file_path' is required and must exist.")

    tool = args.get("tool", "xxd")
    if tool == "xxd":
        xxd = _require_tool("xxd")
        cmd = [xxd]
        if "length" in args:
            cmd.extend(["-l", str(args["length"])])
        if "seek" in args:
            cmd.extend(["-s", str(args["seek"])])
        if args.get("plain", False):
            cmd.append("-p")
        cmd.append(file_path)
    else:
        hexdump = _require_tool("hexdump")
        cmd = [hexdump, "-C"]
        if "length" in args:
            cmd.extend(["-n", str(args["length"])])
        if "seek" in args:
            cmd.extend(["-s", str(args["seek"])])
        cmd.append(file_path)

    result = _run_cmd(cmd, timeout=30)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    return {"ok": True, "result": result["stdout"], "command": result["command"]}


# --- GDB ---
@register("gdbDebug")
def gdb_debug(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run GDB with commands.
    Args: binary_path (required), commands (list), core_file, pid, args (program args)
    """
    binary = args.get("binary_path")
    if not binary or not os.path.isfile(binary):
        raise ToolError("Parameter 'binary_path' is required and must exist.")

    gdb = _require_tool("gdb")
    commands = args.get("commands", ["info files", "info functions", "bt"])

    cmd = [gdb, "-q", "-ex", "set confirm off"]
    for c in commands:
        cmd.extend(["-ex", c])
    cmd.extend(["-ex", "quit", binary])

    if "core_file" in args:
        cmd = [gdb, "-q", "-ex", "bt", "-ex", "quit", binary, args["core_file"]]
    if "pid" in args:
        cmd = [gdb, "-q", "-ex", f"attach {args['pid']}"] + [f"-ex {c}" for c in commands] + ["-ex", "detach", "-ex", "quit"]

    result = _run_cmd(cmd, timeout=60)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    return {"ok": True, "result": result["stdout"], "command": result["command"]}


# --- PWNDBG / GEF ---
@register("pwndbgAnalyze")
def pwndbg_analyze(args: Dict[str, Any]) -> Dict[str, Any]:
    """Run pwndbg analysis (requires pwndbg installed in gdb)."""
    return gdb_debug({
        "binary_path": args.get("binary_path"),
        "commands": ["pwndbg> context", "pwndbg> ropper", "pwndbg> got", "pwndbg> heap", "pwndbg> vmmap"]
    })


@register("gefAnalyze")
def gef_analyze(args: Dict[str, Any]) -> Dict[str, Any]:
    """Run GEF analysis (requires GEF installed in gdb)."""
    return gdb_debug({
        "binary_path": args.get("binary_path"),
        "commands": ["gef➤  checksec", "gef➤  got", "gef➤  heap", "gef➤  vmmap", "gef➤  ropper"]
    })


# --- CHECKSEC ---
@register("checksec")
def checksec_binary(args: Dict[str, Any]) -> Dict[str, Any]:
    """Check binary protections (NX, PIE, RELRO, Canary, Fortify)."""
    file_path = args.get("file_path")
    if not file_path or not os.path.isfile(file_path):
        raise ToolError("Parameter 'file_path' is required and must exist.")

    checksec = _find_tool("checksec")
    if checksec:
        cmd = [checksec, "--file", file_path, "--output", "json"]
        result = _run_cmd(cmd, timeout=30)
        if result["success"]:
            try:
                return {"ok": True, "result": json.loads(result["stdout"]), "command": result["command"]}
            except Exception:
                pass

    # Fallback: use readelf
    return readelf_info({"file_path": file_path, "headers": True, "segments": True, "dynamic": True})


__all__ = [
    "ghidra_analyze", "r2_analyze", "r2_decompile", "binwalk_scan",
    "strings_extract", "objdump_disasm", "readelf_info", "nm_symbols",
    "ldd_deps", "file_identify", "hexdump_view", "gdb_debug",
    "pwndbg_analyze", "gef_analyze", "checksec_binary"
]