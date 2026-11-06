"""Render real CLI output (with ANSI colours) into an animated terminal GIF.

Nothing is faked: callers pass the exact text a command printed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

BG = (26, 26, 25)
FG = (240, 239, 236)
DIM = (150, 149, 140)
CHROME = (44, 44, 42)
PALETTE = {
    30: (26, 26, 25), 31: (230, 103, 103), 32: (12, 163, 12), 33: (250, 178, 25),
    34: (57, 135, 229), 35: (213, 81, 129), 36: (25, 158, 112), 37: (240, 239, 236),
}
BG_PALETTE = {41: (208, 59, 59), 42: (12, 163, 12), 43: (250, 178, 25)}
_SGR = re.compile(r"\x1b\[([0-9;]*)m")


def load_font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    candidates = [("/System/Library/Fonts/Menlo.ttc", 1 if bold else 0)]
    try:
        from matplotlib import font_manager

        weight = "bold" if bold else "normal"
        candidates.append((font_manager.findfont(
            font_manager.FontProperties(family="DejaVu Sans Mono", weight=weight)), 0))
    except ImportError:
        pass
    for path, index in candidates:
        if Path(path).exists():
            return ImageFont.truetype(path, size, index=index)
    return ImageFont.load_default()


@dataclass
class Span:
    text: str
    fg: tuple[int, int, int]
    bg: tuple[int, int, int] | None
    bold: bool


def parse_ansi(line: str) -> list[Span]:
    spans: list[Span] = []
    fg, bg, bold, dim = FG, None, False, False
    pos = 0
    for match in _SGR.finditer(line):
        if match.start() > pos:
            spans.append(Span(line[pos:match.start()], DIM if dim else fg, bg, bold))
        codes = [int(c) for c in match.group(1).split(";") if c] or [0]
        for code in codes:
            if code == 0:
                fg, bg, bold, dim = FG, None, False, False
            elif code == 1:
                bold = True
            elif code == 2:
                dim = True
            elif code in PALETTE:
                fg = PALETTE[code]
            elif code in BG_PALETTE:
                bg = BG_PALETTE[code]
        pos = match.end()
    if pos < len(line):
        spans.append(Span(line[pos:], DIM if dim else fg, bg, bold))
    return spans


class Terminal:
    def __init__(self, cols: int = 112, rows: int = 26, size: int = 15, title: str = "") -> None:
        self.font, self.bold = load_font(size), load_font(size, bold=True)
        box = self.font.getbbox("M")
        self.cw = self.font.getlength("M")
        self.ch = int((box[3] - box[1]) * 1.75)
        self.cols, self.rows, self.title = cols, rows, title
        self.pad, self.bar = 18, 34
        self.width = int(self.cw * cols + 2 * self.pad)
        self.height = self.ch * rows + 2 * self.pad + self.bar

    def frame(self, lines: list[str], cursor: bool = False) -> Image.Image:
        img = Image.new("RGB", (self.width, self.height), BG)
        draw = ImageDraw.Draw(img)
        draw.rectangle([0, 0, self.width, self.bar], fill=CHROME)
        for i, color in enumerate([(236, 106, 94), (245, 191, 79), (98, 197, 84)]):
            draw.ellipse([14 + i * 20, 11, 26 + i * 20, 23], fill=color)
        if self.title:
            tw = self.font.getlength(self.title)
            draw.text(((self.width - tw) / 2, 9), self.title, font=self.font, fill=DIM)
        visible = lines[-self.rows:]
        for row, line in enumerate(visible):
            x = self.pad
            y = self.bar + self.pad + row * self.ch
            for span in parse_ansi(line):
                width = self.font.getlength(span.text)
                if span.bg:
                    draw.rectangle([x, y - 2, x + width, y + self.ch - 6], fill=span.bg)
                fg = (20, 20, 20) if span.bg and span.fg == FG and span.bg != BG_PALETTE[41] else span.fg
                draw.text((x, y), span.text, font=self.bold if span.bold else self.font, fill=fg)
                x += width
            if cursor and row == len(visible) - 1:
                draw.rectangle([x + 2, y, x + self.cw, y + self.ch - 6], fill=FG)
        return img


def session(term: Terminal, scenes: list[tuple[str, str]], prompt: str = "$ ",
            type_ms: int = 45, line_ms: int = 55, hold_ms: int = 2600):
    """Yield (frame, duration_ms) for typed commands followed by their real output."""
    screen: list[str] = []
    for command, output in scenes:
        typed = ""
        for ch in command:
            typed += ch
            yield term.frame(screen + [f"\x1b[32m{prompt}\x1b[0m{typed}"], cursor=True), type_ms
        screen.append(f"\x1b[32m{prompt}\x1b[0m{command}")
        yield term.frame(screen), 350
        for line in output.splitlines():
            screen.append(line)
            yield term.frame(screen), line_ms
        yield term.frame(screen + [f"\x1b[32m{prompt}\x1b[0m"], cursor=True), hold_ms
        screen.append("")


def save_gif(frames, path: Path) -> None:
    images, durations = [], []
    for image, duration in frames:
        images.append(image.convert("P", palette=Image.Palette.ADAPTIVE, colors=64))
        durations.append(duration)
    images[0].save(path, save_all=True, append_images=images[1:], duration=durations,
                   loop=0, optimize=True, disposal=1)
