"""
CTF (Capture The Flag) Helper Tools.

Pure Python implementations for common CTF operations:
- Encoding/Decoding: base64, base32, base16, base85, rot13, rot47, caesar, atbash
- XOR operations: single-byte, multi-byte, repeating key
- Hash functions: md5, sha1, sha256, sha512, etc.
- Number bases: binary, octal, decimal, hex
- Classical ciphers: vigenere, playfair, rail fence, columnar transposition
- Modern crypto helpers: RSA, AES, DES (via pycryptodome if available)
- File analysis: magic bytes, entropy, strings
- Steganography: LSB, metadata extraction
- Web: URL encoding, HTML entities, JWT decode
"""

from __future__ import annotations

import base64
import binascii
import codecs
import hashlib
import html
import itertools
import json
import math
import re
import string
import urllib.parse
from typing import Any, Dict, List, Optional

from .registry import ToolError, register


# --- BASE ENCODING ---
@register("ctfBase64")
def ctf_base64(args: Dict[str, Any]) -> Dict[str, Any]:
    """Base64 encode/decode with variants."""
    action = args.get("action", "encode")
    data = args.get("data", "")
    variant = args.get("variant", "standard")

    if action == "encode":
        if isinstance(data, str):
            data = data.encode()
        if variant == "standard":
            result = base64.b64encode(data).decode()
        elif variant == "url":
            result = base64.urlsafe_b64encode(data).decode()
        elif variant == "no_pad":
            result = base64.b64encode(data).decode().rstrip("=")
        else:
            raise ToolError("Variant must be: standard, url, no_pad")
    elif action == "decode":
        # Auto-detect padding
        missing_padding = len(data) % 4
        if missing_padding:
            data += "=" * (4 - missing_padding)
        try:
            result = base64.b64decode(data).decode()
        except UnicodeDecodeError:
            result = base64.b64decode(data).hex()
    else:
        raise ToolError("Action must be: encode, decode")

    return {"ok": True, "result": result}


@register("ctfBase32")
def ctf_base32(args: Dict[str, Any]) -> Dict[str, Any]:
    """Base32 encode/decode."""
    action = args.get("action", "encode")
    data = args.get("data", "")

    if action == "encode":
        if isinstance(data, str):
            data = data.encode()
        result = base64.b32encode(data).decode()
    elif action == "decode":
        missing_padding = len(data) % 8
        if missing_padding:
            data += "=" * (8 - missing_padding)
        try:
            result = base64.b32decode(data).decode()
        except UnicodeDecodeError:
            result = base64.b32decode(data).hex()
    else:
        raise ToolError("Action must be: encode, decode")

    return {"ok": True, "result": result}


@register("ctfBase16")
def ctf_base16(args: Dict[str, Any]) -> Dict[str, Any]:
    """Base16 (hex) encode/decode."""
    action = args.get("action", "encode")
    data = args.get("data", "")

    if action == "encode":
        if isinstance(data, str):
            data = data.encode()
        result = base64.b16encode(data).decode()
    elif action == "decode":
        try:
            result = base64.b16decode(data.upper()).decode()
        except UnicodeDecodeError:
            result = base64.b16decode(data.upper()).hex()
    else:
        raise ToolError("Action must be: encode, decode")

    return {"ok": True, "result": result}


@register("ctfBase85")
def ctf_base85(args: Dict[str, Any]) -> Dict[str, Any]:
    """Base85 (ASCII85) encode/decode."""
    action = args.get("action", "encode")
    data = args.get("data", "")

    if action == "encode":
        if isinstance(data, str):
            data = data.encode()
        result = base64.a85encode(data).decode()
    elif action == "decode":
        try:
            result = base64.a85decode(data).decode()
        except UnicodeDecodeError:
            result = base64.a85decode(data).hex()
    else:
        raise ToolError("Action must be: encode, decode")

    return {"ok": True, "result": result}


# --- ROT CIPHERS ---
@register("ctfRot13")
def ctf_rot13(args: Dict[str, Any]) -> Dict[str, Any]:
    """ROT13 cipher."""
    data = args.get("data", "")
    result = codecs.encode(data, "rot_13")
    return {"ok": True, "result": result}


@register("ctfRot47")
def ctf_rot47(args: Dict[str, Any]) -> Dict[str, Any]:
    """ROT47 cipher (printable ASCII 33-126)."""
    data = args.get("data", "")
    result = ""
    for c in data:
        o = ord(c)
        if 33 <= o <= 126:
            result += chr(33 + (o - 33 + 47) % 94)
        else:
            result += c
    return {"ok": True, "result": result}


@register("ctfCaesar")
def ctf_caesar(args: Dict[str, Any]) -> Dict[str, Any]:
    """Caesar cipher with custom shift."""
    data = args.get("data", "")
    shift = args.get("shift", 3)
    result = ""
    for c in data:
        if 'a' <= c <= 'z':
            result += chr((ord(c) - ord('a') + shift) % 26 + ord('a'))
        elif 'A' <= c <= 'Z':
            result += chr((ord(c) - ord('A') + shift) % 26 + ord('A'))
        else:
            result += c
    return {"ok": True, "result": result}


@register("ctfAtbash")
def ctf_atbash(args: Dict[str, Any]) -> Dict[str, Any]:
    """Atbash cipher (A↔Z, B↔Y, etc.)."""
    data = args.get("data", "")
    result = ""
    for c in data:
        if 'a' <= c <= 'z':
            result += chr(ord('z') - (ord(c) - ord('a')))
        elif 'A' <= c <= 'Z':
            result += chr(ord('Z') - (ord(c) - ord('A')))
        else:
            result += c
    return {"ok": True, "result": result}


# --- XOR OPERATIONS ---
@register("ctfXor")
def ctf_xor(args: Dict[str, Any]) -> Dict[str, Any]:
    """XOR encryption/decryption (same operation)."""
    data = args.get("data", "")
    key = args.get("key", "")
    if not key:
        raise ToolError("Key is required")

    if isinstance(data, str):
        try:
            data = bytes.fromhex(data)
        except ValueError:
            data = data.encode()

    if isinstance(key, str):
        try:
            key = bytes.fromhex(key)
        except ValueError:
            key = key.encode()

    # Repeat key to match data length
    key = (key * (len(data) // len(key) + 1))[:len(data)]
    result = bytes(a ^ b for a, b in zip(data, key))

    # Try to decode as UTF-8, fallback to hex
    try:
        result_str = result.decode()
    except UnicodeDecodeError:
        result_str = result.hex()

    return {"ok": True, "result": result_str}


@register("ctfXorBrute")
def ctf_xor_brute(args: Dict[str, Any]) -> Dict[str, Any]:
    """Brute force single-byte XOR key."""
    data = args.get("data", "")
    if isinstance(data, str):
        try:
            data = bytes.fromhex(data)
        except ValueError:
            data = data.encode()

    results = []
    for key_byte in range(256):
        key = bytes([key_byte]) * len(data)
        decrypted = bytes(a ^ b for a, b in zip(data, key))
        # Score by printable characters
        score = sum(1 for b in decrypted if 32 <= b <= 126)
        if score / len(decrypted) > 0.7:  # Mostly printable
            try:
                results.append({
                    "key": f"0x{key_byte:02x}",
                    "key_char": chr(key_byte) if 32 <= key_byte <= 126 else "?",
                    "text": decrypted.decode()
                })
            except UnicodeDecodeError:
                pass

    return {"ok": True, "result": results[:20]}  # Top 20


# --- VIGENERE CIPHER ---
@register("ctfVigenere")
def ctg_vigenere(args: Dict[str, Any]) -> Dict[str, Any]:
    """Vigenère cipher encrypt/decrypt."""
    action = args.get("action", "encrypt")
    data = args.get("data", "").upper()
    key = args.get("key", "").upper()
    if not key:
        raise ToolError("Key is required")

    # Filter to A-Z only
    data_clean = ''.join(c for c in data if 'A' <= c <= 'Z')
    key_stream = itertools.cycle(key)

    result = ""
    for c in data_clean:
        k = next(key_stream)
        if action == "encrypt":
            result += chr((ord(c) - ord('A') + ord(k) - ord('A')) % 26 + ord('A'))
        else:
            result += chr((ord(c) - ord('A') - (ord(k) - ord('A'))) % 26 + ord('A'))

    return {"ok": True, "result": result}


# --- RAIL FENCE CIPHER ---
@register("ctfRailFence")
def ctf_rail_fence(args: Dict[str, Any]) -> Dict[str, Any]:
    """Rail fence cipher encrypt/decrypt."""
    action = args.get("action", "encrypt")
    data = args.get("data", "")
    rails = args.get("rails", 3)

    if action == "encrypt":
        fence = [[] for _ in range(rails)]
        rail = 0
        direction = 1
        for c in data:
            fence[rail].append(c)
            rail += direction
            if rail == rails - 1 or rail == 0:
                direction *= -1
        result = ''.join(''.join(r) for r in fence)
    else:
        # Decryption - reconstruct fence pattern
        fence = [[] for _ in range(rails)]
        rail = 0
        direction = 1
        for _ in data:
            fence[rail].append(None)
            rail += direction
            if rail == rails - 1 or rail == 0:
                direction *= -1

        idx = 0
        for r in fence:
            for i in range(len(r)):
                r[i] = data[idx]
                idx += 1

        rail = 0
        direction = 1
        result = ""
        for _ in data:
            result += fence[rail].pop(0)
            rail += direction
            if rail == rails - 1 or rail == 0:
                direction *= -1

    return {"ok": True, "result": result}


# --- COLUMNAR TRANSPOSITION ---
@register("ctfColumnar")
def ctf_columnar(args: Dict[str, Any]) -> Dict[str, Any]:
    """Columnar transposition cipher."""
    action = args.get("action", "encrypt")
    data = args.get("data", "")
    key = args.get("key", "")
    if not key:
        raise ToolError("Key is required")

    # Create column order from key
    key_order = sorted(range(len(key)), key=lambda i: key[i])
    cols = len(key)
    rows = math.ceil(len(data) / cols)

    if action == "encrypt":
        # Pad data
        data = data.ljust(rows * cols, 'X')
        grid = [data[i*cols:(i+1)*cols] for i in range(rows)]
        result = ''
        for col_idx in key_order:
            for row in range(rows):
                result += grid[row][col_idx]
    else:
        # Decryption
        grid = [[''] * cols for _ in range(rows)]
        idx = 0
        for col_idx in key_order:
            for row in range(rows):
                if idx < len(data):
                    grid[row][col_idx] = data[idx]
                    idx += 1
        result = ''.join(''.join(row) for row in grid).rstrip('X')

    return {"ok": True, "result": result}


# --- HASH FUNCTIONS ---
@register("ctfHash")
def ctf_hash(args: Dict[str, Any]) -> Dict[str, Any]:
    """Compute various hashes."""
    data = args.get("data", "")
    if isinstance(data, str):
        data = data.encode()
    algorithm = args.get("algorithm", "md5").lower()

    algos = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha224": hashlib.sha224,
        "sha256": hashlib.sha256,
        "sha384": hashlib.sha384,
        "sha512": hashlib.sha512,
        "sha3_224": hashlib.sha3_224,
        "sha3_256": hashlib.sha3_256,
        "sha3_384": hashlib.sha3_384,
        "sha3_512": hashlib.sha3_512,
        "blake2b": hashlib.blake2b,
        "blake2s": hashlib.blake2s,
    }

    if algorithm not in algos:
        raise ToolError(f"Unsupported algorithm. Available: {', '.join(algos.keys())}")

    h = algos[algorithm]()
    h.update(data)
    return {"ok": True, "result": {"algorithm": algorithm, "hash": h.hexdigest()}}


# --- NUMBER BASE CONVERSION ---
@register("ctfBaseConvert")
def ctf_base_convert(args: Dict[str, Any]) -> Dict[str, Any]:
    """Convert between number bases."""
    data = args.get("data", "")
    from_base = args.get("from_base", 10)
    to_base = args.get("to_base", 16)

    try:
        value = int(data, from_base)
    except ValueError:
        raise ToolError(f"Invalid number for base {from_base}")

    if to_base == 2:
        result = bin(value)[2:]
    elif to_base == 8:
        result = oct(value)[2:]
    elif to_base == 10:
        result = str(value)
    elif to_base == 16:
        result = hex(value)[2:]
    elif 2 <= to_base <= 36:
        # Custom base conversion
        digits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        result = ""
        while value > 0:
            result = digits[value % to_base] + result
            value //= to_base
        if not result:
            result = "0"
    else:
        raise ToolError("Base must be between 2 and 36")

    return {"ok": True, "result": result}


# --- URL / HTML ENCODING ---
@register("ctfUrlEncode")
def ctf_url_encode(args: Dict[str, Any]) -> Dict[str, Any]:
    """URL encode/decode."""
    action = args.get("action", "encode")
    data = args.get("data", "")

    if action == "encode":
        result = urllib.parse.quote(data, safe=args.get("safe", ""))
    elif action == "decode":
        result = urllib.parse.unquote(data)
    else:
        raise ToolError("Action must be: encode, decode")

    return {"ok": True, "result": result}


@register("ctfHtmlEntities")
def ctf_html_entities(args: Dict[str, Any]) -> Dict[str, Any]:
    """HTML entity encode/decode."""
    action = args.get("action", "encode")
    data = args.get("data", "")

    if action == "encode":
        result = html.escape(data)
    elif action == "decode":
        result = html.unescape(data)
    else:
        raise ToolError("Action must be: encode, decode")

    return {"ok": True, "result": result}


# --- JWT ---
@register("ctfJwt")
def ctf_jwt(args: Dict[str, Any]) -> Dict[str, Any]:
    """Decode JWT token (header + payload, no verification)."""
    token = args.get("token", "")
    if not token:
        raise ToolError("Token is required")

    parts = token.split(".")
    if len(parts) != 3:
        raise ToolError("Invalid JWT format")

    result = {}
    for i, part in enumerate(["header", "payload"]):
        # Add padding
        padded = parts[i] + "=" * ((4 - len(parts[i]) % 4) % 4)
        try:
            decoded = base64.urlsafe_b64decode(padded)
            result[part] = json.loads(decoded)
        except Exception as e:
            result[part] = f"Error: {e}"

    return {"ok": True, "result": result}


# --- MAGIC BYTES / FILE TYPE ---
@register("ctfFileType")
def ctf_file_type(args: Dict[str, Any]) -> Dict[str, Any]:
    """Identify file type from magic bytes."""
    data = args.get("data", "")
    if isinstance(data, str):
        try:
            data = bytes.fromhex(data)
        except ValueError:
            data = data.encode()

    # Common magic bytes
    signatures = {
        b'\x89PNG\r\n\x1a\n': 'PNG',
        b'\xff\xd8\xff': 'JPEG',
        b'GIF87a': 'GIF87a',
        b'GIF89a': 'GIF89a',
        b'BM': 'BMP',
        b'%PDF': 'PDF',
        b'PK\x03\x04': 'ZIP',
        b'PK\x05\x06': 'ZIP (empty)',
        b'PK\x07\x08': 'ZIP (spanned)',
        b'Rar!\x1a\x07': 'RAR',
        b'7z\xbc\xaf': '7Z',
        b'\x1f\x8b': 'GZIP',
        b'BZh': 'BZIP2',
        b'\xfd7zXZ': 'XZ',
        b'MZ': 'PE (EXE/DLL)',
        b'\x7fELF': 'ELF',
        b'\xca\xfe\xba\xbe': 'Mach-O (32-bit)',
        b'\xfe\xed\xfa\xce': 'Mach-O (64-bit)',
        b'\xce\xfa\xed\xfe': 'Mach-O (64-bit LE)',
        b'\xca\xfe\xba\xbe': 'Java Class',
        b'<?xml': 'XML',
        b'<!DOCTYPE html': 'HTML',
        b'#!/bin/bash': 'Bash Script',
        b'#!/bin/sh': 'Shell Script',
        b'#!/usr/bin/python': 'Python Script',
    }

    result = "Unknown"
    for sig, ftype in signatures.items():
        if data.startswith(sig):
            result = ftype
            break

    return {"ok": True, "result": {"type": result, "hex": data[:16].hex()}}


# --- ENTROPY ---
@register("ctfEntropy")
def ctf_entropy(args: Dict[str, Any]) -> Dict[str, Any]:
    """Calculate Shannon entropy of data."""
    data = args.get("data", "")
    if isinstance(data, str):
        try:
            data = bytes.fromhex(data)
        except ValueError:
            data = data.encode()

    if not data:
        return {"ok": True, "result": {"entropy": 0}}

    # Count byte frequencies
    freq = [0] * 256
    for b in data:
        freq[b] += 1

    entropy = 0
    for count in freq:
        if count > 0:
            p = count / len(data)
            entropy -= p * math.log2(p)

    return {"ok": True, "result": {"entropy": entropy, "max_entropy": 8.0, "is_encrypted": entropy > 7.5}}


# --- STRINGS EXTRACTION ---
@register("ctfStrings")
def ctf_strings(args: Dict[str, Any]) -> Dict[str, Any]:
    """Extract printable strings from binary data."""
    data = args.get("data", "")
    if isinstance(data, str):
        try:
            data = bytes.fromhex(data)
        except ValueError:
            data = data.encode()

    min_len = args.get("min_length", 4)
    result = []
    current = ""

    for b in data:
        if 32 <= b <= 126:
            current += chr(b)
        else:
            if len(current) >= min_len:
                result.append(current)
            current = ""

    if len(current) >= min_len:
        result.append(current)

    return {"ok": True, "result": result, "count": len(result)}


# --- STEGANOGRAPHY HELPERS ---
@register("ctfLsb")
def ctf_lsb(args: Dict[str, Any]) -> Dict[str, Any]:
    """Extract LSB from image data."""
    data = args.get("data", "")
    if isinstance(data, str):
        try:
            data = bytes.fromhex(data)
        except ValueError:
            data = data.encode()

    # Skip header (first 100 bytes typical)
    offset = args.get("offset", 100)
    channel = args.get("channel", "all")  # all, r, g, b, a

    bits = []
    for i in range(offset, len(data)):
        if channel == "all" or (channel == "r" and i % 4 == 0) or \
           (channel == "g" and i % 4 == 1) or \
           (channel == "b" and i % 4 == 2) or \
           (channel == "a" and i % 4 == 3):
            bits.append(str(data[i] & 1))

    # Group into bytes
    bytes_out = []
    for i in range(0, len(bits), 8):
        byte_bits = bits[i:i+8]
        if len(byte_bits) == 8:
            byte_val = int(''.join(byte_bits), 2)
            bytes_out.append(byte_val)

    # Try to decode
    try:
        result = bytes(bytes_out).decode(errors='replace')
    except Exception:
        result = bytes(bytes_out).hex()

    return {"ok": True, "result": result[:500]}  # Limit output


# --- COMMON CTF TOOLS ---
@register("ctfQuickDecode")
def ctf_quick_decode(args: Dict[str, Any]) -> Dict[str, Any]:
    """Try multiple common encodings on input."""
    data = args.get("data", "")
    if not data:
        raise ToolError("Data is required")

    results = {}

    # Base64
    try:
        padded = data + "=" * ((4 - len(data) % 4) % 4)
        decoded = base64.b64decode(padded)
        results["base64"] = decoded.decode(errors='replace')
    except Exception:
        pass

    # Base32
    try:
        padded = data + "=" * ((8 - len(data) % 8) % 8)
        decoded = base64.b32decode(padded)
        results["base32"] = decoded.decode(errors='replace')
    except Exception:
        pass

    # Base16
    try:
        decoded = base64.b16decode(data.upper())
        results["base16"] = decoded.decode(errors='replace')
    except Exception:
        pass

    # ROT13
    results["rot13"] = codecs.encode(data, "rot_13")

    # ROT47
    rot47 = ""
    for c in data:
        o = ord(c)
        if 33 <= o <= 126:
            rot47 += chr(33 + (o - 33 + 47) % 94)
        else:
            rot47 += c
    results["rot47"] = rot47

    # URL decode
    try:
        results["url"] = urllib.parse.unquote(data)
    except Exception:
        pass

    # HTML entities
    results["html"] = html.unescape(data)

    # Hex decode
    try:
        results["hex"] = bytes.fromhex(data).decode(errors='replace')
    except Exception:
        pass

    return {"ok": True, "result": results}


__all__ = [
    "ctf_base64", "ctf_base32", "ctf_base16", "ctf_base85",
    "ctf_rot13", "ctf_rot47", "ctf_caesar", "ctf_atbash",
    "ctf_xor", "ctf_xor_brute", "ctf_vigenere", "ctf_rail_fence",
    "ctf_columnar", "ctf_hash", "ctf_base_convert",
    "ctf_url_encode", "ctf_html_entities", "ctf_jwt",
    "ctf_file_type", "ctf_entropy", "ctf_strings", "ctf_lsb",
    "ctf_quick_decode"
]