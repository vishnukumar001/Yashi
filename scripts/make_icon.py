#!/usr/bin/env python3
"""
Generate the Yashi app icon (build/icon.png) and convert it to icon.icns.

Produces a 1024x1024 PNG with a smooth purple→cyan radial-gradient orb on a
dark rounded-square background, matching the Yashi splash/brand identity.
Requires only the Python standard library (zlib + struct) so it runs anywhere.

Usage:
    python3 scripts/make_icon.py
Output:
    build/icon.png    (1024x1024 master)
    build/icon.icns   (via iconutil + sips, macOS only)
"""
from __future__ import annotations

import math
import os
import struct
import subprocess
import sys
import zlib
from pathlib import Path


# ---------------------------------------------------------------------------
# Minimal 8-bit RGBA PNG writer (standard library only).
# ---------------------------------------------------------------------------
def _png_chunk(tag: bytes, data: bytes) -> bytes:
    return (
        struct.pack(">I", len(data))
        + tag
        + data
        + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    )


def write_png(path: Path, width: int, height: int, rgba: bytes) -> None:
    """Write raw RGBA pixel bytes to a PNG file."""
    header = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)  # 8-bit, RGBA
    # Filter type 0 (None) per scanline.
    raw = bytearray()
    stride = width * 4
    for y in range(height):
        raw.append(0)
        raw.extend(rgba[y * stride:(y + 1) * stride])
    idat = zlib.compress(bytes(raw), 9)
    png = header + _png_chunk(b"IHDR", ihdr) + _png_chunk(b"IDAT", idat) + _png_chunk(b"IEND", b"")
    path.write_bytes(png)


# ---------------------------------------------------------------------------
# Color helpers.
# ---------------------------------------------------------------------------
def lerp(a: float, b: float, t: float) -> float:
    return a + (b - a) * t


def smoothstep(edge0: float, edge1: float, x: float) -> float:
    t = max(0.0, min(1.0, (x - edge0) / (edge1 - edge0)))
    return t * t * (3.0 - 2.0 * t)


# ---------------------------------------------------------------------------
# Render the icon.
# ---------------------------------------------------------------------------
def render_icon(size: int = 1024) -> bytes:
    """Render a Yashi-style icon into RGBA bytes."""
    w = h = size
    # Dark background base color (matches app backgroundColor #0a0a0f).
    bg = (10, 10, 15)
    # Outer rounded-square "squircle" with soft inset.
    corner = size * 0.2235  # macOS Big Sur+ squircle-ish ratio

    # Gradient orb center and radius.
    cx, cy = size * 0.5, size * 0.46
    r_outer = size * 0.34

    px = bytearray(w * h * 4)

    for y in range(h):
        for x in range(w):
            # --- Squircle mask (rounded square background) ---------------------
            # Distance to nearest rounded-rect edge.
            dx = max(corner - x, x - (w - corner), 0.0)
            dy = max(corner - y, y - (h - corner), 0.0)
            corner_dist = math.hypot(dx, dy)
            inside_squircle = corner_dist <= corner
            # Anti-alias the squircle edge.
            squircle_alpha = 1.0 - smoothstep(corner - 1.5, corner + 1.5, corner_dist)
            if squircle_alpha <= 0.0:
                # Fully transparent outside the squircle.
                continue

            # --- Radial gradient orb (purple → cyan) --------------------------
            d = math.hypot(x - cx, y - cy) / r_outer
            t = max(0.0, min(1.0, d))
            # Purple (#7c5cff) at center → cyan (#48c6ef) at edge.
            orb_r = lerp(0x7C, 0x48, t)
            orb_g = lerp(0x5C, 0xC6, t)
            orb_b = lerp(0xFF, 0xEF, t)

            # Soft falloff so the orb glows and fades into the dark bg.
            orb_alpha = (1.0 - smoothstep(0.75, 1.05, d)) * 1.0
            # Inner highlight: brighter near the very center/top for sheen.
            sheen = math.hypot(x - (cx - r_outer * 0.18), y - (cy - r_outer * 0.28))
            sheen_t = max(0.0, min(1.0, sheen / (r_outer * 0.5)))
            sheen_boost = (1.0 - smoothstep(0.0, 1.0, sheen_t)) * 0.45
            orb_r = min(255.0, orb_r + 255.0 * sheen_boost * 0.5)
            orb_g = min(255.0, orb_g + 255.0 * sheen_boost * 0.5)
            orb_b = min(255.0, orb_b + 255.0 * sheen_boost * 0.5)

            # --- Composite orb over the dark background -----------------------
            out_r = lerp(bg[0], orb_r, orb_alpha)
            out_g = lerp(bg[1], orb_g, orb_alpha)
            out_b = lerp(bg[2], orb_b, orb_alpha)

            i = (y * w + x) * 4
            px[i] = int(out_r)
            px[i + 1] = int(out_g)
            px[i + 2] = int(out_b)
            px[i + 3] = int(255.0 * squircle_alpha)

    return bytes(px)


# ---------------------------------------------------------------------------
# macOS iconset → icns conversion.
# ---------------------------------------------------------------------------
ICONSET_SIZES = [16, 32, 64, 128, 256, 512, 1024]


def build_iconset(master_png: Path, iconset_dir: Path) -> None:
    """Create a .iconset folder of all required sizes via sips."""
    iconset_dir.mkdir(parents=True, exist_ok=True)
    # Normal + @2x pairs expected by iconutil.
    pairs = [
        (16, "icon_16x16.png"),
        (32, "icon_16x16@2x.png"),
        (32, "icon_32x32.png"),
        (64, "icon_32x32@2x.png"),
        (128, "icon_128x128.png"),
        (256, "icon_128x128@2x.png"),
        (256, "icon_256x256.png"),
        (512, "icon_256x256@2x.png"),
        (512, "icon_512x512.png"),
        (1024, "icon_512x512@2x.png"),
    ]
    for px_size, name in pairs:
        out = iconset_dir / name
        subprocess.run(
            ["sips", "-s", "format", "png",
             "-z", str(px_size), str(px_size),
             str(master_png), "--out", str(out)],
            check=True, capture_output=True,
        )


def main() -> int:
    build_dir = Path(__file__).resolve().parent.parent / "build"
    build_dir.mkdir(parents=True, exist_ok=True)
    master = build_dir / "icon.png"
    icns = build_dir / "icon.icns"

    print(f"[icon] Rendering 1024x1024 master → {master}")
    rgba = render_icon(1024)
    write_png(master, 1024, 1024, rgba)
    print(f"[icon] Wrote {master} ({master.stat().st_size} bytes)")

    if sys.platform == "darwin":
        iconset = build_dir / "icon.iconset"
        print(f"[icon] Building iconset via sips → {iconset}")
        build_iconset(master, iconset)
        print(f"[icon] Converting iconset → {icns} via iconutil")
        subprocess.run(
            ["iconutil", "-c", "icns", str(iconset), "-o", str(icns)],
            check=True, capture_output=True,
        )
        # Clean up the intermediate iconset folder.
        for f in iconset.iterdir():
            f.unlink()
        iconset.rmdir()
        print(f"[icon] Wrote {icns} ({icns.stat().st_size} bytes)")
    else:
        print("[icon] Not on macOS — skipping icon.icns generation.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
