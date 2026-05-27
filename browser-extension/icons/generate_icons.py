#!/usr/bin/env python3
"""
Generate ConfigTrace browser-extension PNG icons from pure Python stdlib.

Why this script exists:
  Chrome Web Store requires PNG icons (16, 32, 48, 128). The dev box this
  prototype was built on has neither ImageMagick nor Pillow installed, so we
  draw the 128x128 master directly using zlib + struct, then downsample via
  macOS `sips`. If `sips` is unavailable, falls back to a simplified flat
  PNG at smaller sizes (still valid — Chrome accepts any correctly-encoded
  PNG at the declared dimensions).

Run:
    python3 generate_icons.py

Output (next to this script):
    icon16.png  icon32.png  icon48.png  icon128.png

Design matches icon.svg in the same directory.
Deterministic — running it twice produces byte-identical PNGs.
"""
import os
import struct
import subprocess
import sys
import zlib

# Palette
BG      = (75, 124, 246, 255)   # #4B7CF6  ConfigTrace brand blue
FG      = (255, 255, 255, 255)  # white CT letters
ALPHA0  = (0,   0,   0,   0)    # transparent

SIZE    = 128
RADIUS  = 22

LETTER_STROKES = (
    # C: left bar, top bar, bottom bar
    (24, 34, 32, 94),
    (24, 34, 60, 42),
    (24, 86, 60, 94),
    # T: top bar, centered vertical
    (68, 34, 104, 42),
    (82, 34,  90, 94),
)


def in_rounded_rect(x, y, x0, y0, x1, y1, r):
    if x < x0 or x >= x1 or y < y0 or y >= y1:
        return False
    # corner-aware test
    if x < x0 + r and y < y0 + r:
        dx, dy = (x0 + r) - x, (y0 + r) - y
        return dx * dx + dy * dy <= r * r
    if x >= x1 - r and y < y0 + r:
        dx, dy = x - (x1 - r - 1), (y0 + r) - y
        return dx * dx + dy * dy <= r * r
    if x < x0 + r and y >= y1 - r:
        dx, dy = (x0 + r) - x, y - (y1 - r - 1)
        return dx * dx + dy * dy <= r * r
    if x >= x1 - r and y >= y1 - r:
        dx, dy = x - (x1 - r - 1), y - (y1 - r - 1)
        return dx * dx + dy * dy <= r * r
    return True


def draw_128():
    pixels = [ALPHA0] * (SIZE * SIZE)
    # rounded square background
    for y in range(SIZE):
        for x in range(SIZE):
            if in_rounded_rect(x, y, 8, 8, 120, 120, RADIUS):
                pixels[y * SIZE + x] = BG
    # letters
    for y in range(SIZE):
        for x in range(SIZE):
            for (x0, y0, x1, y1) in LETTER_STROKES:
                if x0 <= x < x1 and y0 <= y < y1:
                    pixels[y * SIZE + x] = FG
                    break
    return pixels


def write_png(path, w, h, pixels):
    """Write an 8-bit RGBA PNG. Stdlib only."""
    raw = bytearray()
    for y in range(h):
        raw.append(0)  # filter type "None"
        for x in range(w):
            r, g, b, a = pixels[y * w + x]
            raw.extend((r, g, b, a))

    def chunk(typ, data):
        length = struct.pack(">I", len(data))
        crc = struct.pack(">I", zlib.crc32(typ + data) & 0xFFFFFFFF)
        return length + typ + data + crc

    ihdr = struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0)
    idat = zlib.compress(bytes(raw), 9)
    out  = b"\x89PNG\r\n\x1a\n"
    out += chunk(b"IHDR", ihdr)
    out += chunk(b"IDAT", idat)
    out += chunk(b"IEND", b"")

    with open(path, "wb") as f:
        f.write(out)


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    pixels_128 = draw_128()
    master = os.path.join(here, "icon128.png")
    write_png(master, SIZE, SIZE, pixels_128)
    print(f"wrote {master}")

    for size in (48, 32, 16):
        out_path = os.path.join(here, f"icon{size}.png")
        try:
            subprocess.run(
                ["sips", "-z", str(size), str(size), master, "--out", out_path],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            print(f"wrote {out_path} (resized via sips)")
        except (FileNotFoundError, subprocess.CalledProcessError):
            # Fallback: draw a flat brand-blue square with a 1px transparent edge.
            simple = [
                BG if 1 <= x < size - 1 and 1 <= y < size - 1 else ALPHA0
                for y in range(size)
                for x in range(size)
            ]
            write_png(out_path, size, size, simple)
            print(f"wrote {out_path} (flat fallback — `sips` unavailable)")


if __name__ == "__main__":
    main()
