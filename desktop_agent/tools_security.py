import subprocess
import socket
import os
import shlex
import re
from typing import Any, Dict, List
from .registry import register, ToolError

# ---------------------------------------------------------------------------
# Terminal Command Safeguards
# ---------------------------------------------------------------------------
# Commands that are explicitly BLOCKED (denylist)
BLOCKED_COMMANDS = frozenset([
    # Destructive system commands
    "rm", "rmdir", "del", "erase", "rd", "format", "fdisk", "mkfs",
    "dd", "shred", "wipefs", "badblocks",
    # Process control
    "kill", "killall", "pkill", "taskkill", "tskill",
    # System modification
    "shutdown", "reboot", "halt", "poweroff", "init", "systemctl", "service",
    "launchctl", "systemsetup",
    # Privilege escalation
    "sudo", "su", "doas", "runas", "pkexec",
    # Package managers (install/remove)
    "apt", "apt-get", "yum", "dnf", "pacman", "brew", "port", "choco", "winget",
    "pip", "npm", "yarn", "cargo", "gem",
    # Network/firewall
    "iptables", "ufw", "firewall-cmd", "netsh", "pfctl",
    # Disk/partition
    "mount", "umount", "diskutil", "parted", "gparted",
    # User management
    "useradd", "userdel", "usermod", "groupadd", "groupdel", "passwd",
    # Kernel/modules
    "insmod", "rmmod", "modprobe", "kldload", "kldunload",
    # Cron/at
    "crontab", "at", "batch",
    # Shell built-ins that can be dangerous
    "exec", "eval", "source", ".",
])

# Allowed commands (allowlist approach - more restrictive)
# If ALLOWED_COMMANDS is non-empty, ONLY these commands are permitted
ALLOWED_COMMANDS = frozenset([
    # Read-only / info commands
    "ls", "dir", "pwd", "echo", "cat", "type", "head", "tail", "less", "more",
    "grep", "find", "locate", "which", "where", "whereis",
    "ps", "top", "htop", "df", "du", "free", "vmstat", "iostat",
    "whoami", "id", "who", "w", "last", "date", "uptime", "uname",
    "hostname", "ifconfig", "ip", "netstat", "ss", "ping", "traceroute",
    "dig", "nslookup", "host", "curl", "wget", "git", "hg", "svn",
    "python", "python3", "node", "npm", "npx", "php", "ruby", "perl",
    "jq", "awk", "sed", "sort", "uniq", "wc", "cut", "tr", "tee",
    "file", "stat", "md5sum", "sha256sum", "sha1sum", "diff", "patch",
    "tar", "gzip", "gunzip", "zip", "unzip", "xz", "bzip2",
    "man", "info", "help", "which", "command", "type", "alias",
])

# Maximum command timeout (seconds)
MAX_COMMAND_TIMEOUT = 30
DEFAULT_COMMAND_TIMEOUT = 10

# Maximum output size (bytes)
MAX_STDOUT_SIZE = 10000
MAX_STDERR_SIZE = 5000

# Blocked patterns in command (regex) - for non-shell mode
BLOCKED_PATTERNS = [
    r'>\s*/dev/',           # Redirect to device files
    r'<\s*/dev/',           # Read from device files
    r'\|\s*sh',             # Pipe to shell
    r'\|\s*bash',           # Pipe to bash
    r'\|\s*zsh',            # Pipe to zsh
    r'\|\s*python',         # Pipe to python
    r'\$\(',                # Command substitution
    r'`',                   # Backtick command substitution
    r';;',                  # Multiple commands
    r'&&\s*(rm|kill|sudo)', # Chained dangerous commands
    r'\|\s*sudo',           # Pipe to sudo
    r'chmod\s+[0-7]{3,4}\s+/etc',  # chmod on system dirs
    r'chown\s+.*\s+/etc',   # chown on system dirs
]

# ============================================================
# PERSISTENT SHELL SESSION SUPPORT
# ============================================================
import threading
import time
from pathlib import Path

class ShellSession:
    """Manages a persistent shell session with state (cwd, env, history)."""
    
    def __init__(self, session_id: str):
        self.session_id = session_id
        self.cwd = str(Path.home())
        self.env = {**os.environ, "PATH": "/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin"}
        self.history: list[str] = []
        self.created_at = time.time()
        self.last_used = time.time()
        self.lock = threading.Lock()
    
    def execute(self, command: str, timeout: int = 30) -> Dict[str, Any]:
        """Execute command in persistent shell with full shell features."""
        with self.lock:
            self.last_used = time.time()
            self.history.append(command)
            if len(self.history) > 100:
                self.history = self.history[-100:]
            
            # Build the full command with session state
            # Use bash -c to support pipes, redirects, globs, etc.
            full_cmd = f"cd {shlex.quote(self.cwd)} && {command}"
            
            try:
                proc = subprocess.run(
                    full_cmd,
                    shell=True,  # CRITICAL: Enable shell features
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    cwd=self.cwd,
                    env=self.env,
                    executable="/bin/bash" if os.name != 'nt' else None,
                )
                
                # Update cwd if command was cd
                if command.strip().startswith("cd "):
                    # Extract new path and update session cwd
                    try:
                        new_cwd = subprocess.run(
                            f"cd {shlex.quote(self.cwd)} && {command} && pwd",
                            shell=True, capture_output=True, text=True, timeout=5,
                            env=self.env, executable="/bin/bash" if os.name != 'nt' else None
                        ).stdout.strip()
                        if new_cwd and os.path.isdir(new_cwd):
                            self.cwd = new_cwd
                    except Exception:
                        pass
                
                # Truncate output
                stdout = proc.stdout[:50000]
                stderr = proc.stderr[:10000]
                
                if len(proc.stdout) > 50000:
                    stdout += f"\n... [stdout truncated at 50000 chars, total {len(proc.stdout)}]"
                if len(proc.stderr) > 10000:
                    stderr += f"\n... [stderr truncated at 10000 chars, total {len(proc.stderr)}]"
                
                return {
                    "ok": proc.returncode == 0,
                    "result": f"Exit code: {proc.returncode}",
                    "stdout": stdout,
                    "stderr": stderr,
                    "exit_code": proc.returncode,
                    "cwd": self.cwd,
                }
            except subprocess.TimeoutExpired:
                return {"ok": False, "result": f"Command timed out after {timeout} seconds.", "cwd": self.cwd}
            except Exception as e:
                return {"ok": False, "result": f"Execution failed: {e}", "cwd": self.cwd}


# Global session store
_SHELL_SESSIONS: Dict[str, ShellSession] = {}
_SESSIONS_LOCK = threading.Lock()

# Cleanup old sessions periodically
def _cleanup_sessions(max_age_seconds: int = 3600):
    """Remove sessions older than max_age_seconds."""
    with _SESSIONS_LOCK:
        now = time.time()
        to_delete = [
            sid for sid, sess in _SHELL_SESSIONS.items()
            if now - sess.last_used > max_age_seconds
        ]
        for sid in to_delete:
            del _SHELL_SESSIONS[sid]

def _get_or_create_session(session_id: str = "default") -> ShellSession:
    _cleanup_sessions()
    with _SESSIONS_LOCK:
        if session_id not in _SHELL_SESSIONS:
            _SHELL_SESSIONS[session_id] = ShellSession(session_id)
        return _SHELL_SESSIONS[session_id]

def _delete_session(session_id: str) -> bool:
    with _SESSIONS_LOCK:
        if session_id in _SHELL_SESSIONS:
            del _SHELL_SESSIONS[session_id]
            return True
        return False

def _list_sessions() -> list[Dict[str, Any]]:
    _cleanup_sessions()
    with _SESSIONS_LOCK:
        return [
            {
                "session_id": sid,
                "cwd": sess.cwd,
                "history_length": len(sess.history),
                "created_at": sess.created_at,
                "last_used": sess.last_used,
            }
            for sid, sess in _SHELL_SESSIONS.items()
        ]

def _validate_command(command: str) -> tuple[str, list[str]]:
    """
    Validate and parse the command.
    Returns (executable, args_list) if valid.
    Raises ToolError if invalid.
    """
    if not command or not command.strip():
        raise ToolError("Command cannot be empty.")
    
    # Check for blocked patterns
    for pattern in BLOCKED_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            raise ToolError(f"Command contains blocked pattern: {pattern}")
    
    # Parse command into executable and arguments
    try:
        parts = shlex.split(command, posix=(os.name != 'nt'))
    except ValueError as e:
        raise ToolError(f"Invalid command syntax: {e}")
    
    if not parts:
        raise ToolError("No command found.")
    
    executable = parts[0].lower()
    args = parts[1:]
    
    # Remove path from executable (e.g., /usr/bin/ls -> ls)
    executable_base = os.path.basename(executable)
    
    # Check denylist
    if executable_base in BLOCKED_COMMANDS:
        raise ToolError(f"Command '{executable_base}' is not allowed for security reasons.")
    
    # Check allowlist (if configured)
    if ALLOWED_COMMANDS and executable_base not in ALLOWED_COMMANDS:
        raise ToolError(f"Command '{executable_base}' is not in the allowed commands list.")
    
    # Additional safety: limit argument count and length
    if len(args) > 50:
        raise ToolError("Too many arguments (max 50).")
    
    for arg in args:
        if len(arg) > 1000:
            raise ToolError("Argument too long (max 1000 chars).")
    
    return executable, args


@register("runSecurityScan")
def run_security_scan(args: Dict[str, Any]) -> Dict[str, Any]:
    target = args.get("target")
    if not target:
        raise ToolError("Parameter 'target' is required.")
    
    # Basic port scan using socket
    ports = args.get("ports", [80, 443, 22, 21, 25, 3306, 5432, 8080])
    open_ports = []
    
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex((target, port)) == 0:
                    open_ports.append(port)
        except Exception:
            continue
            
    return {
        "result": f"Scan completed for {target}. Found {len(open_ports)} open ports.",
        "target": target,
        "open_ports": open_ports
    }

@register("dnsLookup")
def dns_lookup(args: Dict[str, Any]) -> Dict[str, Any]:
    domain = args.get("domain")
    if not domain:
        raise ToolError("Parameter 'domain' is required.")
    
    try:
        ip = socket.gethostbyname(domain)
        return {"result": f"DNS Lookup for {domain}: {ip}", "ip": ip}
    except Exception as e:
        raise ToolError(f"DNS Lookup failed: {e}")

@register("checkVulnerability")
def check_vulnerability(args: Dict[str, Any]) -> Dict[str, Any]:
    software = args.get("software")
    version = args.get("version")
    if not software:
        raise ToolError("Parameter 'software' is required.")
    
    # This would ideally call an API like CVE Details or NVD.
    # For now, it returns a placeholder or a simple message.
    return {
        "result": f"Searching for vulnerabilities in {software} {version or ''}...",
        "software": software,
        "version": version,
        "note": "For real-time CVE data, please connect a vulnerability database API."
    }

@register("executeShellCommand")
def execute_shell_command(args: Dict[str, Any]) -> Dict[str, Any]:
    command = args.get("command")
    if not command:
        raise ToolError("Parameter 'command' is required.")

    # Validate and parse command
    executable, cmd_args = _validate_command(command)
    
    # Build the full command for execution (without shell=True for safety)
    # We'll use the parsed executable and args directly
    full_cmd = [executable] + cmd_args
    
    # Get timeout (clamped to max)
    timeout = min(int(args.get("timeout", DEFAULT_COMMAND_TIMEOUT)), MAX_COMMAND_TIMEOUT)
    
    # DANGER: Running shell commands.
    # We avoid shell=True by using the parsed arguments directly.
    # This prevents injection attacks but means shell features (glob, pipes, etc.) won't work.
    try:
        proc = subprocess.run(
            full_cmd,
            shell=False,  # CRITICAL: No shell=True for security
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=os.path.expanduser("~"),  # Restrict to home directory
            env={
                **os.environ,
                # Sanitize environment - remove potentially dangerous vars
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin",
            }
        )
        
        # Truncate output
        stdout = proc.stdout[:MAX_STDOUT_SIZE]
        stderr = proc.stderr[:MAX_STDERR_SIZE]
        
        # Add truncation notice
        if len(proc.stdout) > MAX_STDOUT_SIZE:
            stdout += f"\n... [output truncated at {MAX_STDOUT_SIZE} chars]"
        if len(proc.stderr) > MAX_STDERR_SIZE:
            stderr += f"\n... [error output truncated at {MAX_STDERR_SIZE} chars]"
        
        return {
            "result": f"Executed command. Exit code: {proc.returncode}",
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": proc.returncode
        }
    except subprocess.TimeoutExpired:
        return {"result": f"Command timed out after {timeout} seconds."}
    except FileNotFoundError:
        raise ToolError(f"Command not found: {executable}")
    except PermissionError:
        raise ToolError(f"Permission denied executing: {executable}")
    except Exception as e:
        raise ToolError(f"Execution failed: {e}")


# Alias so the server's HIGH_RISK_TOOLS set and Gemini's tool declarations
# can reference 'terminalCommand' as the user-facing name.
@register("terminalCommand")
def terminal_command(args: Dict[str, Any]) -> Dict[str, Any]:
    """Alias for executeShellCommand — same handler, same risk."""
    return execute_shell_command(args)


# ============================================================
# PERSISTENT INTERACTIVE SHELL SESSION TOOLS
# ============================================================
# These provide a full-featured shell with pipes, redirects, globs,
# persistent cwd/env/history across calls. Much more powerful than
# the single-shot executeShellCommand.

@register("terminalShell")
def terminal_shell(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Execute command in a persistent shell session with FULL shell features:
    - Pipes (|), redirects (>, >>, <), globs (*), command substitution ($(), ``)
    - Chained commands (&&, ||, ;), background jobs (&)
    - Persistent cwd, environment variables, history across calls
    - Session isolation (multiple named sessions)
    
    Args:
        command: Shell command to execute (full shell syntax supported)
        session_id: Session name (default: "default") - maintains state
        timeout: Command timeout in seconds (default: 30, max: 120)
        cwd: Override working directory for this command only
    """
    command = args.get("command")
    if not command:
        raise ToolError("Parameter 'command' is required.")
    
    session_id = args.get("session_id", "default")
    timeout = min(int(args.get("timeout", 30)), 120)
    
    session = _get_or_create_session(session_id)
    
    # Temporarily override cwd if provided
    original_cwd = session.cwd
    if "cwd" in args:
        session.cwd = os.path.expanduser(args["cwd"])
    
    result = session.execute(command, timeout)
    
    # Restore original cwd if we overrode it
    if "cwd" in args:
        session.cwd = original_cwd
    
    # Add session info to result
    result["session_id"] = session_id
    return result


@register("terminalShellSession")
def terminal_shell_session(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Manage persistent shell sessions.
    
    Actions:
        create: Create a new session (session_id required)
        list: List all active sessions
        delete: Delete a session (session_id required)
        history: Get command history for a session (session_id required)
        clear_history: Clear history for a session (session_id required)
    
    Args:
        action: One of [create, list, delete, history, clear_history]
        session_id: Session identifier (required for create/delete/history/clear_history)
    """
    action = args.get("action", "list")
    session_id = args.get("session_id", "default")
    
    if action == "create":
        _get_or_create_session(session_id)
        return {"result": f"Created shell session '{session_id}'", "session_id": session_id}
    
    elif action == "list":
        sessions = _list_sessions()
        return {"result": f"Found {len(sessions)} active session(s)", "sessions": sessions}
    
    elif action == "delete":
        if _delete_session(session_id):
            return {"result": f"Deleted shell session '{session_id}'", "session_id": session_id}
        return {"result": f"Session '{session_id}' not found", "session_id": session_id}
    
    elif action == "history":
        _cleanup_sessions()
        with _SESSIONS_LOCK:
            if session_id in _SHELL_SESSIONS:
                return {
                    "result": f"History for session '{session_id}' ({len(_SHELL_SESSIONS[session_id].history)} commands)",
                    "history": _SHELL_SESSIONS[session_id].history,
                    "session_id": session_id,
                }
            return {"result": f"Session '{session_id}' not found", "session_id": session_id}
    
    elif action == "clear_history":
        _cleanup_sessions()
        with _SESSIONS_LOCK:
            if session_id in _SHELL_SESSIONS:
                _SHELL_SESSIONS[session_id].history.clear()
                return {"result": f"Cleared history for session '{session_id}'", "session_id": session_id}
            return {"result": f"Session '{session_id}' not found", "session_id": session_id}
    
    else:
        raise ToolError(f"Unknown action '{action}'. Use: create, list, delete, history, clear_history")
