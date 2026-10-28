#!/usr/bin/env python3
"""Render a terminal-style animated GIF from a captured run transcript.

Frames reveal the real captured lines one by one, with a typed effect on the
newest line and a short pause on the result lines. The transcript content is
the genuine captured session; the animation is only presentation.
"""
import sys
from PIL import Image, ImageDraw, ImageFont

FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
BG = (13, 17, 23)
PANEL = (22, 27, 34)
FG = (230, 237, 243)
DIM = (139, 148, 158)
GREEN = (63, 185, 80)
RED = (248, 81, 73)
BLUE = (88, 166, 255)
YELLOW = (211, 153, 34)

def colorize(line):
    s = line.strip()
    if s.startswith("[+]"):
        return GREEN
    if s.startswith("[!]"):
        return RED
    if s.startswith("[*]"):
        return BLUE
    if s.startswith("    "):
        return DIM
    return FG

def layout(lines, fs=22, pad=36):
    font = ImageFont.truetype(FONT, fs)
    probe = Image.new("RGB", (10, 10))
    d = ImageDraw.Draw(probe)
    longest = max(d.textlength(t or " ", font=font) for t in lines)
    header = 64
    W = int(longest) + pad * 2 + 8
    H = header + len(lines) * (fs + 10) + pad
    return W, H, font

def frame(lines, shown, typed, W, H, font, fs, cursor_on):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    # title bar
    d.rectangle([0, 0, W, 40], fill=PANEL)
    for i, c in enumerate((RED, YELLOW, GREEN)):
        d.ellipse([16 + i * 26, 13, 28 + i * 26, 25], fill=c)
    d.text((100, 9), "php-worker-pin · pinned run", font=ImageFont.truetype(BOLD, 18), fill=DIM)
    y = 56
    for i, line in enumerate(lines):
        if i > shown:
            break
        text = line
        if i == shown and typed is not None:
            text = line[:typed]
        col = colorize(line)
        d.text((36, y), text or " ", font=font, fill=col)
        if i == shown and cursor_on:
            tw = d.textlength(text or " ", font=font)
            d.rectangle([36 + tw + 2, y + 3, 36 + tw + 12, y + fs], fill=col)
        y += fs + 10
    return img

def main():
    src, out = sys.argv[1], sys.argv[2]
    title = sys.argv[3] if len(sys.argv) > 3 else "php-worker-pin"
    lines = open(src).read().rstrip("\n").split("\n")
    W, H, font = layout(lines)
    fs = 22
    frames = []
    # typing: reveal line by line; newest line types in chunks
    for i, line in enumerate(lines):
        n = len(line)
        step = max(1, n // 5)
        if n <= 8:
            frames.append((frame(lines, i, n, W, H, font, fs, True), 90))
        else:
            for t in range(0, n + 1, step):
                frames.append((frame(lines, i, min(t, n), W, H, font, fs, True), 28))
        # pause on key lines
        s = line.strip()
        if s.startswith("[+]") or "summary" in s or s.startswith("uid="):
            frames.append((frame(lines, i, n, W, H, font, fs, False), 500))
        else:
            frames.append((frame(lines, i, n, W, H, font, fs, False), 120))
    # end hold with blinking cursor
    frames.append((frame(lines, len(lines) - 1, None, W, H, font, fs, True), 400))
    frames.append((frame(lines, len(lines) - 1, None, W, H, font, fs, False), 400))
    frames.append((frame(lines, len(lines) - 1, None, W, H, font, fs, True), 400))
    imgs, durs = [], []
    for img, ms in frames:
        imgs.append(img)
        durs.append(ms)
    imgs[0].save(out, save_all=True, append_images=imgs[1:], duration=durs, loop=0, optimize=True)
    import os
    print(f"saved {out}: {len(imgs)} frames, {W}x{H}, {os.path.getsize(out) // 1024} KB")

if __name__ == "__main__":
    main()
