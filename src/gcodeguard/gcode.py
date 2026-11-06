"""Tolerant G-code line parser.

Handles Marlin/RepRap-style commands (``G1 X10 Y-2.5 F3000``), Klipper extended
commands (``SET_HEATER_TEMPERATURE HEATER=extruder TARGET=210``), OctoPrint host
commands (``@pause``), line numbers, checksums, and both comment styles.

The parser is deliberately *at least as lenient* as common firmware: if firmware
would accept a spelling (``m104s300``, ``M104 S 300``, ``N12 M104 S300*45``),
GcodeGuard must parse it the same way, or an attacker could hide commands in the
gap between what the firewall sees and what the printer runs.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field

_LINE_NUMBER = re.compile(r"^N\d+\s*", re.IGNORECASE)
_CHECKSUM = re.compile(r"\*\d+\s*$")
_PAREN_COMMENT = re.compile(r"\([^)]*\)")
_CLASSIC_CODE = re.compile(r"^([GMT])\s*(\d+)(?:\.(\d+))?", re.IGNORECASE)
_CLASSIC_PARAM = re.compile(r"([A-Z])\s*([-+]?(?:\d+\.?\d*|\.\d+))?", re.IGNORECASE)
_EXT_PARAM = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)=(\"[^\"]*\"|'[^']*'|\S*)")
_EXT_CODE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

#: Marlin commands whose argument is free text rather than letter/number pairs.
STRING_ARG_CODES = frozenset(
    {"M23", "M28", "M30", "M32", "M33", "M117", "M118", "M928", "M919", "M16", "M115"}
)


@dataclass(frozen=True)
class Command:
    """One parsed G-code line."""

    raw: str
    code: str = ""
    params: Mapping[str, str | None] = field(default_factory=dict)
    text: str | None = None
    comment: str = ""
    line_no: int | None = None
    kind: str = "empty"  # classic | extended | host | empty

    @property
    def is_empty(self) -> bool:
        return self.kind == "empty"

    @property
    def letter(self) -> str:
        return self.code[:1] if self.kind == "classic" else ""

    def has(self, key: str) -> bool:
        return key.upper() in self.params

    def num(self, key: str, default: float | None = None) -> float | None:
        """Numeric value of a parameter, or ``default`` if absent/unparseable."""
        value = self.params.get(key.upper())
        if value is None:
            return default
        try:
            return float(value.strip("\"'"))
        except ValueError:
            return default

    def str_param(self, key: str, default: str | None = None) -> str | None:
        value = self.params.get(key.upper())
        if value is None:
            return default
        return value.strip("\"'")

    def to_line(self) -> str:
        """Re-serialise without comments/line numbers."""
        if self.kind == "empty":
            return ""
        if self.kind == "classic":
            if self.text is not None:
                return f"{self.code} {self.text}".rstrip()
            parts = [self.code] + [f"{k}{'' if v is None else v}" for k, v in self.params.items()]
            return " ".join(parts)
        parts = [self.code] + [f"{k}={'' if v is None else v}" for k, v in self.params.items()]
        return " ".join(parts)

    def with_params(self, updates: Mapping[str, str]) -> Command:
        params = dict(self.params)
        for key, value in updates.items():
            params[key.upper()] = value
        new = Command(
            raw="",
            code=self.code,
            params=params,
            text=self.text,
            comment=self.comment,
            line_no=self.line_no,
            kind=self.kind,
        )
        return Command(
            raw=new.to_line(),
            code=new.code,
            params=new.params,
            text=new.text,
            comment=new.comment,
            line_no=new.line_no,
            kind=new.kind,
        )


def _strip_comments(line: str) -> tuple[str, str]:
    comment_parts: list[str] = []
    if ";" in line:
        line, semi = line.split(";", 1)
        comment_parts.append(semi.strip())
    paren = _PAREN_COMMENT.findall(line)
    if paren:
        comment_parts.extend(p[1:-1].strip() for p in paren)
        line = _PAREN_COMMENT.sub(" ", line)
    return line.strip(), " ".join(p for p in comment_parts if p)


def _normalise_code(letter: str, number: str, sub: str | None) -> str:
    code = f"{letter.upper()}{int(number)}"
    if sub is not None:
        code += f".{int(sub)}"
    return code


def parse_line(line: str, line_no: int | None = None) -> Command:
    """Parse a single line of G-code. Never raises."""
    raw = line.rstrip("\r\n")
    body, comment = _strip_comments(raw)
    body = _CHECKSUM.sub("", body).strip()
    body = _LINE_NUMBER.sub("", body).strip()
    if not body:
        return Command(raw=raw, comment=comment, line_no=line_no)

    if body.startswith("@"):
        word, _, rest = body[1:].partition(" ")
        return Command(
            raw=raw,
            code="@" + word.upper(),
            text=rest.strip() or None,
            comment=comment,
            line_no=line_no,
            kind="host",
        )

    match = _CLASSIC_CODE.match(body)
    first_word = body.split(None, 1)[0]
    if match and not _is_extended_word(first_word):
        code = _normalise_code(match.group(1), match.group(2), match.group(3))
        rest = body[match.end() :].strip()
        if code in STRING_ARG_CODES:
            return Command(
                raw=raw,
                code=code,
                text=rest or None,
                comment=comment,
                line_no=line_no,
                kind="classic",
            )
        params: dict[str, str | None] = {}
        for letter, value in _CLASSIC_PARAM.findall(rest):
            params[letter.upper()] = value if value != "" else None
        return Command(
            raw=raw, code=code, params=params, comment=comment, line_no=line_no, kind="classic"
        )

    word, _, rest = body.partition(" ")
    if not _EXT_CODE.match(word):
        # Garbage the firmware will reject anyway; keep it visible to rules.
        return Command(
            raw=raw, code=word.upper(), text=rest or None, comment=comment, line_no=line_no,
            kind="extended",
        )
    ext_params: dict[str, str | None] = {}
    for key, value in _EXT_PARAM.findall(rest):
        ext_params[key.upper()] = value
    return Command(
        raw=raw,
        code=word.upper(),
        params=ext_params,
        text=rest.strip() or None,
        comment=comment,
        line_no=line_no,
        kind="extended",
    )


def _is_extended_word(word: str) -> bool:
    """``G28`` is classic; ``GET_POSITION`` and ``M104_SAFE`` are extended (Klipper macros)."""
    return "_" in word or (len(word) > 1 and word[1:].isalpha())


def parse_lines(lines: list[str] | tuple[str, ...]) -> list[Command]:
    return [parse_line(line, i + 1) for i, line in enumerate(lines)]
