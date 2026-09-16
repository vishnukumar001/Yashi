"""
Cryptography & Hash Analysis Tools.

Wraps: hashcat, john, gpg, openssl, cyberchef (via node), and pure-Python crypto ops.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
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


# --- HASHCAT ---
@register("hashcatCrack")
def hashcat_crack(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run hashcat for password/hash cracking.
    Args: hash_file (or hash), hash_mode, wordlist, rules, attack_mode (0=straight, 1=combinator, 3=brute, 6=hybrid), mask, session, restore, show, username, remove, potfile_path, workload_profile
    """
    hashcat = _require_tool("hashcat")
    cmd = [hashcat]

    # Hash input
    if "hash" in args:
        # Write hash to temp file
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".hash", delete=False) as f:
            f.write(args["hash"])
            hash_file = f.name
        cmd.extend([hash_file])
    elif "hash_file" in args:
        cmd.extend([args["hash_file"]])
    else:
        raise ToolError("Either 'hash' or 'hash_file' is required.")

    if "hash_mode" in args:
        cmd.extend(["-m", str(args["hash_mode"])])
    if "wordlist" in args:
        cmd.extend(["-a", "0", args["wordlist"]])
    if "attack_mode" in args:
        cmd.extend(["-a", str(args["attack_mode"])])
    if "mask" in args:
        cmd.extend(["-a", "3", args["mask"]])
    if "rules" in args:
        cmd.extend(["-r", args["rules"]])
    if "session" in args:
        cmd.extend(["--session", args["session"]])
    if args.get("restore", False):
        cmd.append("--restore")
    if args.get("show", False):
        cmd.append("--show")
    if args.get("username", False):
        cmd.append("--username")
    if args.get("remove", False):
        cmd.append("--remove")
    if "potfile_path" in args:
        cmd.extend(["--potfile-path", args["potfile_path"]])
    if "workload_profile" in args:
        cmd.extend(["-w", str(args["workload_profile"])])

    # Output
    cmd.extend(["--outfile", "-", "--outfile-format", "2"])

    result = _run_cmd(cmd, timeout=3600)

    if not result["success"]:
        # hashcat returns non-zero on no cracks found
        if "exhausted" in result["stderr"].lower() or "no hashes" in result["stderr"].lower():
            return {"ok": True, "result": {"cracked": 0, "message": "No hashes cracked"}, "command": result["command"]}
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    # Parse output
    cracked = []
    for line in result["stdout"].strip().split("\n"):
        if line.strip():
            try:
                cracked.append(json.loads(line))
            except Exception:
                pass

    return {"ok": True, "result": {"cracked": len(cracked), "hashes": cracked}, "command": result["command"]}


@register("hashcatBenchmark")
def hashcat_benchmark(args: Dict[str, Any]) -> Dict[str, Any]:
    """Run hashcat benchmark."""
    hashcat = _require_tool("hashcat")
    cmd = [hashcat, "-b"]

    if "hash_mode" in args:
        cmd.extend(["-m", str(args["hash_mode"])])

    result = _run_cmd(cmd, timeout=300)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    return {"ok": True, "result": result["stdout"], "command": result["command"]}


# --- JOHN THE RIPPER ---
@register("johnCrack")
def john_crack(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run John the Ripper for password cracking.
    Args: hash_file (or hash), format, wordlist, rules, session, restore, show, fork, mask, incremental
    """
    john = _require_tool("john")
    cmd = [john]

    if "hash" in args:
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".hash", delete=False) as f:
            f.write(args["hash"])
            hash_file = f.name
        cmd.append(hash_file)
    elif "hash_file" in args:
        cmd.append(args["hash_file"])
    else:
        raise ToolError("Either 'hash' or 'hash_file' is required.")

    if "format" in args:
        cmd.extend(["--format", args["format"]])
    if "wordlist" in args:
        cmd.extend(["--wordlist", args["wordlist"]])
    if "rules" in args:
        cmd.extend(["--rules", args["rules"]])
    if "session" in args:
        cmd.extend(["--session", args["session"]])
    if args.get("restore", False):
        cmd.append("--restore")
    if args.get("show", False):
        cmd.append("--show")
    if "fork" in args:
        cmd.extend(["--fork", str(args["fork"])])
    if "mask" in args:
        cmd.extend(["--mask", args["mask"]])
    if args.get("incremental", False):
        cmd.append("--incremental")

    result = _run_cmd(cmd, timeout=3600)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    # Show cracked passwords
    show_cmd = [john]
    if "hash_file" in args:
        show_cmd.append(args["hash_file"])
    elif "hash" in args:
        show_cmd.append(hash_file)
    show_cmd.append("--show")
    show_result = _run_cmd(show_cmd, timeout=30)

    return {"ok": True, "result": show_result["stdout"], "command": result["command"]}


# --- GPG ---
@register("gpgEncrypt")
def gpg_encrypt(args: Dict[str, Any]) -> Dict[str, Any]:
    """Encrypt data with GPG."""
    gpg = _require_tool("gpg")
    cmd = [gpg, "--encrypt", "--armor"]

    if "recipient" in args:
        cmd.extend(["-r", args["recipient"]])
    if "output" in args:
        cmd.extend(["-o", args["output"]])

    data = args.get("data", "")
    if "input_file" in args:
        cmd.append(args["input_file"])
        result = _run_cmd(cmd, timeout=60)
    else:
        result = _run_cmd(cmd, timeout=60, input_data=data)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    return {"ok": True, "result": result["stdout"] or "Encrypted to " + args.get("output", "stdout"), "command": result["command"]}


@register("gpgDecrypt")
def gpg_decrypt(args: Dict[str, Any]) -> Dict[str, Any]:
    """Decrypt data with GPG."""
    gpg = _require_tool("gpg")
    cmd = [gpg, "--decrypt"]

    if "output" in args:
        cmd.extend(["-o", args["output"]])

    if "input_file" in args:
        cmd.append(args["input_file"])
        result = _run_cmd(cmd, timeout=60)
    else:
        data = args.get("data", "")
        result = _run_cmd(cmd, timeout=60, input_data=data)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    return {"ok": True, "result": result["stdout"], "command": result["command"]}


@register("gpgSign")
def gpg_sign(args: Dict[str, Any]) -> Dict[str, Any]:
    """Sign data with GPG."""
    gpg = _require_tool("gpg")
    cmd = [gpg, "--sign", "--armor"]

    if "output" in args:
        cmd.extend(["-o", args["output"]])
    if "detach" in args and args["detach"]:
        cmd.append("--detach-sign")

    data = args.get("data", "")
    if "input_file" in args:
        cmd.append(args["input_file"])
        result = _run_cmd(cmd, timeout=60)
    else:
        result = _run_cmd(cmd, timeout=60, input_data=data)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    return {"ok": True, "result": result["stdout"], "command": result["command"]}


@register("gpgVerify")
def gpg_verify(args: Dict[str, Any]) -> Dict[str, Any]:
    """Verify GPG signature."""
    gpg = _require_tool("gpg")
    cmd = [gpg, "--verify"]

    if "signature_file" in args:
        cmd.append(args["signature_file"])
    if "data_file" in args:
        cmd.append(args["data_file"])

    result = _run_cmd(cmd, timeout=60)

    return {"ok": True, "result": result["stdout"], "verified": result["returncode"] == 0, "command": result["command"]}


@register("gpgKeyGen")
def gpg_keygen(args: Dict[str, Any]) -> Dict[str, Any]:
    """Generate GPG key pair."""
    gpg = _require_tool("gpg")

    # Create batch input for unattended key generation
    batch_input = f"""%echo Generating GPG key
Key-Type: {args.get("key_type", "RSA")}
Key-Length: {args.get("key_length", 4096)}
Subkey-Type: {args.get("subkey_type", "RSA")}
Subkey-Length: {args.get("subkey_length", 4096)}
Name-Real: {args.get("name", "Yashi User")}
Name-Email: {args.get("email", "yashi@local")}
Expire-Date: {args.get("expire", "0")}
%no-protection
%commit
%echo Done
"""

    cmd = [gpg, "--batch", "--generate-key"]
    result = _run_cmd(cmd, timeout=120, input_data=batch_input)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    return {"ok": True, "result": result["stdout"], "command": result["command"]}


@register("gpgListKeys")
def gpg_list_keys(args: Dict[str, Any]) -> Dict[str, Any]:
    """List GPG keys."""
    gpg = _require_tool("gpg")
    cmd = [gpg, "--list-keys", "--with-colons"]

    if args.get("secret", False):
        cmd = [gpg, "--list-secret-keys", "--with-colons"]

    result = _run_cmd(cmd, timeout=30)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    # Parse colon-separated output
    keys = []
    current_key = {}
    for line in result["stdout"].split("\n"):
        if not line:
            continue
        parts = line.split(":")
        if parts[0] == "pub" or parts[0] == "sec":
            if current_key:
                keys.append(current_key)
            current_key = {"type": parts[0], "key_id": parts[4], "fingerprint": parts[9] if len(parts) > 9 else ""}
        elif parts[0] == "uid":
            if "uids" not in current_key:
                current_key["uids"] = []
            current_key["uids"].append(parts[9] if len(parts) > 9 else "")
    if current_key:
        keys.append(current_key)

    return {"ok": True, "result": keys, "command": result["command"]}


# --- OPENSSL ---
@register("opensslHash")
def openssl_hash(args: Dict[str, Any]) -> Dict[str, Any]:
    """Compute hash using OpenSSL."""
    openssl = _require_tool("openssl")
    algorithm = args.get("algorithm", "sha256")
    data = args.get("data", "")
    binary = args.get("binary", False)

    cmd = [openssl, "dgst", f"-{algorithm}"]
    if binary:
        cmd.append("-binary")

    if "input_file" in args:
        cmd.append(args["input_file"])
        result = _run_cmd(cmd, timeout=30)
    else:
        result = _run_cmd(cmd, timeout=30, input_data=data)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    # Output format: algorithm(stdin)= hash
    output = result["stdout"].strip()
    hash_value = output.split("=")[-1].strip() if "=" in output else output

    return {"ok": True, "result": {"algorithm": algorithm, "hash": hash_value}, "command": result["command"]}


@register("opensslEnc")
def openssl_enc(args: Dict[str, Any]) -> Dict[str, Any]:
    """Encrypt/decrypt with OpenSSL."""
    openssl = _require_tool("openssl")
    cipher = args.get("cipher", "aes-256-cbc")
    action = "-e" if args.get("encrypt", True) else "-d"
    password = args.get("password", "")
    salt = args.get("salt", True)
    base64_out = args.get("base64", True)

    cmd = [openssl, "enc", f"-{cipher}", action]
    if not salt:
        cmd.append("-nosalt")
    if base64_out:
        cmd.append("-base64")
    if password:
        cmd.extend(["-pass", f"pass:{password}"])
    else:
        cmd.extend(["-pass", "stdin"])

    data = args.get("data", "")
    if "input_file" in args:
        cmd.extend(["-in", args["input_file"]])
    if "output_file" in args:
        cmd.extend(["-out", args["output_file"]])

    result = _run_cmd(cmd, timeout=60, input_data=data if not "input_file" in args else password)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    return {"ok": True, "result": result["stdout"] if not "output_file" in args else f"Written to {args['output_file']}", "command": result["command"]}


@register("opensslGenRSA")
def openssl_genrsa(args: Dict[str, Any]) -> Dict[str, Any]:
    """Generate RSA key pair."""
    openssl = _require_tool("openssl")
    bits = args.get("bits", 4096)

    cmd = [openssl, "genrsa", str(bits)]
    if "output_file" in args:
        cmd.extend(["-out", args["output_file"]])
    if args.get("encrypt_key", False):
        password = args.get("password", "")
        cmd.extend(["-aes256", "-passout", f"pass:{password}"])

    result = _run_cmd(cmd, timeout=60)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    return {"ok": True, "result": result["stdout"] if not "output_file" in args else f"Key written to {args['output_file']}", "command": result["command"]}


@register("opensslX509")
def openssl_x509(args: Dict[str, Any]) -> Dict[str, Any]:
    """Parse X.509 certificate."""
    openssl = _require_tool("openssl")
    cmd = [openssl, "x509", "-noout", "-text"]

    if "input_file" in args:
        cmd.extend(["-in", args["input_file"]])
    else:
        data = args.get("data", "")
        return {"ok": False, "error": "input_file required for x509 parsing"}

    result = _run_cmd(cmd, timeout=30)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    return {"ok": True, "result": result["stdout"], "command": result["command"]}


# --- PURE PYTHON CRYPTO ---
@register("cryptoHash")
def crypto_hash(args: Dict[str, Any]) -> Dict[str, Any]:
    """Compute hash using Python hashlib (no external tools)."""
    data = args.get("data", "")
    if "input_file" in args:
        with open(args["input_file"], "rb") as f:
            data = f.read()
    elif isinstance(data, str):
        data = data.encode()

    algorithm = args.get("algorithm", "sha256").lower()
    try:
        h = hashlib.new(algorithm)
    except ValueError:
        raise ToolError(f"Unsupported algorithm: {algorithm}")

    h.update(data)
    return {
        "ok": True,
        "result": {
            "algorithm": algorithm,
            "hash": h.hexdigest(),
            "hash_bytes": h.digest().hex()
        }
    }


@register("cryptoHmac")
def crypto_hmac(args: Dict[str, Any]) -> Dict[str, Any]:
    """Compute HMAC."""
    key = args.get("key", "").encode()
    data = args.get("data", "").encode()
    algorithm = args.get("algorithm", "sha256").lower()

    try:
        h = hmac.new(key, data, getattr(hashlib, algorithm))
    except AttributeError:
        raise ToolError(f"Unsupported algorithm: {algorithm}")

    return {
        "ok": True,
        "result": {
            "algorithm": f"hmac-{algorithm}",
            "hmac": h.hexdigest()
        }
    }


@register("cryptoBase64")
def crypto_base64(args: Dict[str, Any]) -> Dict[str, Any]:
    """Base64 encode/decode."""
    action = args.get("action", "encode")
    data = args.get("data", "")

    if action == "encode":
        if isinstance(data, str):
            data = data.encode()
        result = base64.b64encode(data).decode()
    elif action == "decode":
        try:
            result = base64.b64decode(data).decode()
        except Exception:
            result = base64.b64decode(data).hex()
    elif action == "url_encode":
        if isinstance(data, str):
            data = data.encode()
        result = base64.urlsafe_b64encode(data).decode()
    elif action == "url_decode":
        result = base64.urlsafe_b64decode(data).decode()
    else:
        raise ToolError("Action must be: encode, decode, url_encode, url_decode")

    return {"ok": True, "result": result}


@register("cryptoHex")
def crypto_hex(args: Dict[str, Any]) -> Dict[str, Any]:
    """Hex encode/decode."""
    action = args.get("action", "encode")
    data = args.get("data", "")

    if action == "encode":
        if isinstance(data, str):
            data = data.encode()
        result = data.hex()
    elif action == "decode":
        result = bytes.fromhex(data).decode(errors="replace")
    else:
        raise ToolError("Action must be: encode, decode")

    return {"ok": True, "result": result}


@register("cryptoRot")
def crypto_rot(args: Dict[str, Any]) -> Dict[str, Any]:
    """ROT13/ROT47 cipher."""
    data = args.get("data", "")
    shift = args.get("shift", 13)
    rot47 = args.get("rot47", False)

    if rot47:
        # ROT47: printable ASCII 33-126
        result = ""
        for c in data:
            o = ord(c)
            if 33 <= o <= 126:
                result += chr(33 + (o - 33 + 47) % 94)
            else:
                result += c
    else:
        # ROT13/ROT-N
        result = ""
        for c in data:
            if 'a' <= c <= 'z':
                result += chr((ord(c) - ord('a') + shift) % 26 + ord('a'))
            elif 'A' <= c <= 'Z':
                result += chr((ord(c) - ord('A') + shift) % 26 + ord('A'))
            else:
                result += c

    return {"ok": True, "result": result}


@register("cryptoXor")
def crypto_xor(args: Dict[str, Any]) -> Dict[str, Any]:
    """XOR encryption/decryption."""
    data = args.get("data", "")
    key = args.get("key", "")
    if not key:
        raise ToolError("Key is required")

    if isinstance(data, str):
        data = data.encode()
    if isinstance(key, str):
        key = key.encode()

    result = bytes(a ^ b for a, b in zip(data, (key * (len(data) // len(key) + 1))[:len(data)]))

    # Try to decode as UTF-8, fallback to hex
    try:
        result_str = result.decode()
    except UnicodeDecodeError:
        result_str = result.hex()

    return {"ok": True, "result": result_str}


# --- CYBERCHEF (via Node.js if available) ---
@register("cyberchefRun")
def cyberchef_run(args: Dict[str, Any]) -> Dict[str, Any]:
    """Run CyberChef recipe (requires Node.js with @gchq/cyberchef)."""
    recipe = args.get("recipe")
    input_data = args.get("input", "")

    if not recipe:
        raise ToolError("Recipe is required (JSON array of operations).")

    # Try to run via Node
    try:
        import subprocess
        node_script = f"""
const {{ CyberChef }} = require('@gchq/cyberchef');
const chef = new CyberChef();
chef.loadRecipe({json.dumps(recipe)});
const result = chef.bake('{input_data.replace("'", "\\'")}');
console.log(JSON.stringify({{result: result[0].toString()}}));
"""
        result = subprocess.run(["node", "-e", node_script], capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            parsed = json.loads(result.stdout.strip())
            return {"ok": True, "result": parsed["result"]}
    except Exception:
        pass

    return {"ok": False, "error": "CyberChef not available. Install @gchq/cyberchef via npm."}


# --- IDENTIFY HASH ---
@register("hashIdentify")
def hash_identify(args: Dict[str, Any]) -> Dict[str, Any]:
    """Identify hash type by length and format."""
    hash_str = args.get("hash", "").strip()
    if not hash_str:
        raise ToolError("Hash is required")

    # Common hash lengths
    hash_types = {
        32: ["MD5", "MD4", "RIPEMD-128"],
        40: ["SHA-1", "RIPEMD-160"],
        48: ["SHA-1 (Base64)"],
        56: ["SHA-224"],
        64: ["SHA-256", "RIPEMD-256", "BLAKE2s", "SHA3-256"],
        88: ["SHA-384 (Base64)"],
        96: ["SHA-384"],
        112: ["SHA-512 (Base64)"],
        128: ["SHA-512", "BLAKE2b", "SHA3-512", "Whirlpool"],
        16: ["DES", "MySQL323", "Half MD5"],
        20: ["MySQL41", "SHA-1 (raw)"],
        41: ["MySQL5", "SHA-1 (mod)"],
        60: ["bcrypt"],
        98: ["sha512crypt"],
    }

    # Check for prefixes
    prefixes = {
        "$1$": "MD5 Crypt",
        "$2a$": "bcrypt",
        "$2b$": "bcrypt",
        "$2y$": "bcrypt",
        "$5$": "SHA-256 Crypt",
        "$6$": "SHA-512 Crypt",
        "$sha1$": "SHA-1 (Django)",
        "$pbkdf2_sha256$": "PBKDF2-SHA256",
        "$argon2i$": "Argon2i",
        "$argon2d$": "Argon2d",
        "$argon2id$": "Argon2id",
    }

    possible = []
    length = len(hash_str)

    if length in hash_types:
        possible.extend(hash_types[length])

    for prefix, name in prefixes.items():
        if hash_str.startswith(prefix):
            possible.insert(0, name)

    # Check character set
    if all(c in "0123456789abcdef" for c in hash_str.lower()):
        charset = "hex"
    elif all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for c in hash_str):
        charset = "base64"
    else:
        charset = "mixed"

    return {
        "ok": True,
        "result": {
            "hash": hash_str,
            "length": length,
            "charset": charset,
            "possible_types": possible[:10],
            "hashcat_modes": _guess_hashcat_modes(possible)
        }
    }


def _guess_hashcat_modes(types: List[str]) -> List[int]:
    """Guess hashcat modes from hash types."""
    mode_map = {
        "MD5": 0,
        "SHA-1": 100,
        "SHA-256": 1400,
        "SHA-512": 1700,
        "bcrypt": 3200,
        "SHA-256 Crypt": 7400,
        "SHA-512 Crypt": 1800,
        "MD5 Crypt": 500,
        "MySQL5": 300,
        "PBKDF2-SHA256": 10900,
    }
    modes = []
    for t in types:
        for k, v in mode_map.items():
            if k.lower() in t.lower():
                modes.append(v)
    return list(set(modes))


__all__ = [
    "hashcat_crack", "hashcat_benchmark", "john_crack",
    "gpg_encrypt", "gpg_decrypt", "gpg_sign", "gpg_verify", "gpg_keygen", "gpg_list_keys",
    "openssl_hash", "openssl_enc", "openssl_genrsa", "openssl_x509",
    "crypto_hash", "crypto_hmac", "crypto_base64", "crypto_hex", "crypto_rot", "crypto_xor",
    "cyberchef_run", "hash_identify"
]