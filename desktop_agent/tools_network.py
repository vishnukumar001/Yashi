"""
Network Analysis & Packet Capture Tools.

Wraps: tshark, tcpdump, netstat, ss, zeek, ntopng, iftop, nethogs, iperf3, socat, nc, nmap (for network discovery).
"""

from __future__ import annotations

import json
import platform
import shlex
import subprocess
import os
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
        extra_paths = ["/usr/local/bin", "/opt/zeek/bin"]
    elif system == "Windows":
        extra_paths = [os.path.expanduser("~/Wireshark"), "C:\\Program Files\\Wireshark"]

    for path_dir in ["/usr/bin", "/bin", "/usr/sbin", "/sbin"] + extra_paths:
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


def _run_cmd(cmd: List[str], timeout: int = 120, input_data: str = "") -> Dict[str, Any]:
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


# --- TSHARK ---
@register("tsharkCapture")
def tshark_capture(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Capture packets with tshark.
    Args: interface, duration, packet_count, filter (BPF), output_file, output_format (json, pcap, pcapng), ring_buffer
    """
    tshark = _require_tool("tshark")
    cmd = [tshark]

    if "interface" in args:
        cmd.extend(["-i", args["interface"]])
    else:
        # Try to get default interface
        pass

    if "filter" in args:
        cmd.extend(["-f", args["filter"]])

    if "duration" in args:
        cmd.extend(["-a", f"duration:{args['duration']}"])
    if "packet_count" in args:
        cmd.extend(["-c", str(args["packet_count"])])

    output_format = args.get("output_format", "json")
    if output_format == "json":
        cmd.extend(["-T", "json"])
    elif output_format in ["pcap", "pcapng"]:
        cmd.extend(["-w", args.get("output_file", "capture.pcapng")])
    else:
        cmd.extend(["-T", "fields", "-e", "frame.number", "-e", "frame.time", "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "_ws.col.Protocol", "-e", "_ws.col.Info"])

    if "ring_buffer" in args:
        cmd.extend(["-b", args["ring_buffer"]])

    if "output_file" in args and output_format != "json":
        cmd.extend(["-w", args["output_file"]])

    result = _run_cmd(cmd, timeout=args.get("duration", 60) + 30)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    if output_format == "json" and result["stdout"]:
        try:
            packets = json.loads(result["stdout"])
            return {"ok": True, "result": packets, "count": len(packets), "command": result["command"]}
        except Exception:
            pass

    return {"ok": True, "result": result["stdout"], "command": result["command"]}


@register("tsharkAnalyze")
def tshark_analyze(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze pcap file with tshark.
    Args: file (required), filter (display filter), fields, output_format (json, text), conversation, endpoints, io_graph
    """
    file_path = args.get("file")
    if not file_path or not os.path.isfile(file_path):
        raise ToolError("Parameter 'file' is required and must exist.")

    tshark = _require_tool("tshark")
    cmd = [tshark, "-r", file_path]

    if "filter" in args:
        cmd.extend(["-Y", args["filter"]])

    if "fields" in args:
        fields = args["fields"]
        if isinstance(fields, list):
            for f in fields:
                cmd.extend(["-e", f])
        else:
            cmd.extend(["-e", fields])
        cmd.extend(["-T", "fields"])

    output_format = args.get("output_format", "json")
    if output_format == "json":
        cmd.extend(["-T", "json"])
    elif output_format == "csv":
        cmd.extend(["-T", "csv"])

    if args.get("conversation", False):
        cmd.extend(["-q", "-z", "conv,tcp"])
    if args.get("endpoints", False):
        cmd.extend(["-q", "-z", "endpoints,tcp"])
    if args.get("io_graph", False):
        cmd.extend(["-q", "-z", "io,phs"])

    result = _run_cmd(cmd, timeout=120)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    if output_format == "json" and result["stdout"]:
        try:
            parsed = json.loads(result["stdout"])
            return {"ok": True, "result": parsed, "count": len(parsed), "command": result["command"]}
        except Exception:
            pass

    return {"ok": True, "result": result["stdout"], "command": result["command"]}


@register("tsharkFollow")
def tshark_follow(args: Dict[str, Any]) -> Dict[str, Any]:
    """Follow TCP/UDP stream in pcap."""
    file_path = args.get("file")
    stream = args.get("stream")
    if not file_path or not os.path.isfile(file_path):
        raise ToolError("Parameter 'file' is required and must exist.")
    if stream is None:
        raise ToolError("Parameter 'stream' (stream index) is required.")

    tshark = _require_tool("tshark")
    cmd = [tshark, "-r", file_path, "-q", "-z", f"follow,tcp,ascii,{stream}"]

    result = _run_cmd(cmd, timeout=60)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    return {"ok": True, "result": result["stdout"], "command": result["command"]}


# --- TCPDUMP ---
@register("tcpdumpCapture")
def tcpdump_capture(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Capture packets with tcpdump.
    Args: interface, filter (BPF), count, duration, output_file, snaplen, promiscuous
    """
    tcpdump = _require_tool("tcpdump")
    cmd = [tcpdump, "-n"]

    if "interface" in args:
        cmd.extend(["-i", args["interface"]])

    if "filter" in args:
        cmd.append(args["filter"])

    if "count" in args:
        cmd.extend(["-c", str(args["count"])])

    if "duration" in args:
        cmd.extend(["-G", str(args["duration"])])

    if "snaplen" in args:
        cmd.extend(["-s", str(args["snaplen"])])
    else:
        cmd.extend(["-s", "65535"])

    if args.get("promiscuous", True):
        pass  # default

    if "output_file" in args:
        cmd.extend(["-w", args["output_file"]])

    result = _run_cmd(cmd, timeout=args.get("duration", 60) + 30)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    return {"ok": True, "result": result["stdout"], "command": result["command"]}


@register("tcpdumpRead")
def tcpdump_read(args: Dict[str, Any]) -> Dict[str, Any]:
    """Read pcap file with tcpdump."""
    file_path = args.get("file")
    if not file_path or not os.path.isfile(file_path):
        raise ToolError("Parameter 'file' is required and must exist.")

    tcpdump = _require_tool("tcpdump")
    cmd = [tcpdump, "-n", "-r", file_path]

    if "filter" in args:
        cmd.append(args["filter"])

    if "count" in args:
        cmd.extend(["-c", str(args["count"])])

    if args.get("verbose", False):
        cmd.append("-v")
    if args.get("very_verbose", False):
        cmd.append("-vv")

    result = _run_cmd(cmd, timeout=60)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    return {"ok": True, "result": result["stdout"], "command": result["command"]}


# --- NETSTAT ---
@register("netstatShow")
def netstat_show(args: Dict[str, Any]) -> Dict[str, Any]:
    """Show network connections with netstat."""
    netstat = _require_tool("netstat")
    cmd = [netstat]

    if args.get("tcp", True):
        cmd.append("-t")
    if args.get("udp", True):
        cmd.append("-u")
    if args.get("listening", False):
        cmd.append("-l")
    if args.get("numeric", True):
        cmd.append("-n")
    if args.get("process", False):
        cmd.append("-p")
    if args.get("extend", False):
        cmd.append("-e")

    result = _run_cmd(cmd, timeout=10)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    lines = result["stdout"].strip().split("\n")
    return {"ok": True, "result": lines, "count": len(lines), "command": result["command"]}


# --- SS (modern netstat replacement) ---
@register("ssShow")
def ss_show(args: Dict[str, Any]) -> Dict[str, Any]:
    """Show socket statistics with ss (faster than netstat)."""
    ss = _require_tool("ss")
    cmd = [ss]

    if args.get("tcp", True):
        cmd.append("-t")
    if args.get("udp", True):
        cmd.append("-u")
    if args.get("listening", False):
        cmd.append("-l")
    if args.get("numeric", True):
        cmd.append("-n")
    if args.get("process", False):
        cmd.append("-p")
    if args.get("extend", False):
        cmd.append("-e")
    if args.get("summary", False):
        cmd.append("-s")

    if "state" in args:
        cmd.extend(["state", args["state"]])

    result = _run_cmd(cmd, timeout=10)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    lines = result["stdout"].strip().split("\n")
    return {"ok": True, "result": lines, "count": len(lines), "command": result["command"]}


# --- ZEEK (Bro) ---
@register("zeekAnalyze")
def zeek_analyze(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze pcap with Zeek (Bro).
    Args: file (required), output_dir, scripts, local_site_policy
    """
    file_path = args.get("file")
    if not file_path or not os.path.isfile(file_path):
        raise ToolError("Parameter 'file' is required and must exist.")

    zeek = _find_tool("zeek") or _find_tool("bro")
    if not zeek:
        raise ToolError("Zeek not found. Install Zeek (formerly Bro).")

    output_dir = args.get("output_dir", "zeek_output")
    cmd = [zeek, "-r", file_path]

    if "scripts" in args:
        for script in args["scripts"]:
            cmd.append(script)
    else:
        cmd.append("local")

    result = _run_cmd(cmd, timeout=300)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    # Zeek writes logs to output directory
    logs = []
    if os.path.isdir(output_dir):
        for f in os.listdir(output_dir):
            if f.endswith(".log"):
                logs.append(f)

    return {"ok": True, "result": {"logs": logs, "output_dir": output_dir}, "command": result["command"]}


@register("zeekLive")
def zeek_live(args: Dict[str, Any]) -> Dict[str, Any]:
    """Run Zeek in live capture mode."""
    interface = args.get("interface")
    if not interface:
        raise ToolError("Parameter 'interface' is required.")

    zeek = _find_tool("zeek") or _find_tool("bro")
    if not zeek:
        raise ToolError("Zeek not found.")

    cmd = [zeek, "-i", interface]

    if "scripts" in args:
        for script in args["scripts"]:
            cmd.append(script)
    else:
        cmd.append("local")

    if "duration" in args:
        # Use timeout
        pass

    result = _run_cmd(cmd, timeout=args.get("duration", 60) + 30)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    return {"ok": True, "result": result["stdout"], "command": result["command"]}


# --- IPerf3 ---
@register("iperf3Test")
def iperf3_test(args: Dict[str, Any]) -> Dict[str, Any]:
    """Run network throughput test with iperf3."""
    iperf3 = _require_tool("iperf3")
    cmd = [iperf3]

    if "server" in args and args["server"]:
        cmd.append("-s")
        if "port" in args:
            cmd.extend(["-p", str(args["port"])])
        if "daemon" in args:
            cmd.append("-D")
    else:
        # Client mode
        if "host" not in args:
            raise ToolError("Parameter 'host' is required for client mode.")
        cmd.extend(["-c", args["host"]])
        if "port" in args:
            cmd.extend(["-p", str(args["port"])])
        if "duration" in args:
            cmd.extend(["-t", str(args["duration"])])
        if "parallel" in args:
            cmd.extend(["-P", str(args["parallel"])])
        if "bandwidth" in args:
            cmd.extend(["-b", args["bandwidth"]])
        if args.get("reverse", False):
            cmd.append("-R")
        if args.get("udp", False):
            cmd.append("-u")

    cmd.extend(["-J"])  # JSON output

    result = _run_cmd(cmd, timeout=args.get("duration", 10) + 30)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    try:
        parsed = json.loads(result["stdout"])
        return {"ok": True, "result": parsed, "command": result["command"]}
    except Exception:
        return {"ok": True, "result": result["stdout"], "command": result["command"]}


# --- SOCAT / NETCAT ---
@register("socatConnect")
def socat_connect(args: Dict[str, Any]) -> Dict[str, Any]:
    """Connect/Listen with socat."""
    socat = _require_tool("socat")
    cmd = [socat]

    listen = args.get("listen", False)
    if listen:
        port = args.get("port", 4444)
        cmd.append(f"TCP-LISTEN:{port},reuseaddr,fork")
    else:
        host = args.get("host")
        port = args.get("port", 4444)
        if not host:
            raise ToolError("Parameter 'host' is required for connect mode.")
        cmd.append(f"TCP:{host}:{port}")

    if "exec" in args:
        cmd.append(f"EXEC:{args['exec']}")

    if args.get("pty", False):
        cmd.append("pty,raw,echo=0")

    result = _run_cmd(cmd, timeout=30)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    return {"ok": True, "result": result["stdout"], "command": result["command"]}


@register("ncConnect")
def nc_connect(args: Dict[str, Any]) -> Dict[str, Any]:
    """Netcat connect/listen."""
    nc = _find_tool("nc") or _find_tool("ncat")
    if not nc:
        raise ToolError("Netcat not found.")

    cmd = [nc]

    if args.get("listen", False):
        cmd.append("-l")
        if "port" in args:
            cmd.extend(["-p", str(args["port"])])
    else:
        host = args.get("host")
        port = args.get("port")
        if not host or not port:
            raise ToolError("Parameters 'host' and 'port' are required.")
        cmd.extend([host, str(port)])

    if args.get("verbose", False):
        cmd.append("-v")
    if args.get("udp", False):
        cmd.append("-u")

    if "execute" in args:
        cmd.extend(["-e", args["execute"]])

    if "timeout" in args:
        cmd.extend(["-w", str(args["timeout"])])

    result = _run_cmd(cmd, timeout=args.get("timeout", 30) + 10)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    return {"ok": True, "result": result["stdout"], "command": result["command"]}


# --- IFTOP / NETHOGS ---
@register("iftopShow")
def iftop_show(args: Dict[str, Any]) -> Dict[str, Any]:
    """Show bandwidth usage per connection (iftop)."""
    iftop = _require_tool("iftop")
    cmd = [iftop, "-t", "-s", str(args.get("duration", 10))]

    if "interface" in args:
        cmd.extend(["-i", args["interface"]])

    result = _run_cmd(cmd, timeout=args.get("duration", 10) + 10)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    return {"ok": True, "result": result["stdout"], "command": result["command"]}


@register("nethogsShow")
def nethogs_show(args: Dict[str, Any]) -> Dict[str, Any]:
    """Show bandwidth per process (nethogs)."""
    nethogs = _require_tool("nethogs")
    cmd = [nethogs, "-t"]

    if "interface" in args:
        cmd.append(args["interface"])

    result = _run_cmd(cmd, timeout=15)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    return {"ok": True, "result": result["stdout"], "command": result["command"]}


# --- NMAP NETWORK DISCOVERY ---
@register("nmapPing")
def nmap_ping(args: Dict[str, Any]) -> Dict[str, Any]:
    """Ping sweep with nmap."""
    target = args.get("target")
    if not target:
        raise ToolError("Parameter 'target' is required.")

    nmap = _require_tool("nmap")
    cmd = [nmap, "-sn", target]

    if "output_format" in args:
        if args["output_format"] == "json":
            cmd.extend(["-oJ", "-"])
        elif args["output_format"] == "xml":
            cmd.extend(["-oX", "-"])

    result = _run_cmd(cmd, timeout=60)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    return {"ok": True, "result": result["stdout"], "command": result["command"]}


# --- ARP / NEIGHBOR ---
@register("arpScan")
def arp_scan(args: Dict[str, Any]) -> Dict[str, Any]:
    """ARP scan local network."""
    arp = _find_tool("arp") or _find_tool("ip")
    if not arp:
        raise ToolError("ARP tools not found.")

    if arp.endswith("ip"):
        cmd = ["ip", "neigh", "show"]
    else:
        cmd = [arp, "-a"]

    result = _run_cmd(cmd, timeout=10)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    return {"ok": True, "result": result["stdout"], "command": result["command"]}


__all__ = [
    "tshark_capture", "tshark_analyze", "tshark_follow",
    "tcpdump_capture", "tcpdump_read",
    "netstat_show", "ss_show",
    "zeek_analyze", "zeek_live",
    "iperf3_test", "socat_connect", "nc_connect",
    "iftop_show", "nethogs_show",
    "nmap_ping", "arp_scan"
]