"""Core value types shared by the parser, rules, and engine."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {Severity.INFO: 0, Severity.WARNING: 1, Severity.CRITICAL: 2}


class Action(str, Enum):
    """What the firewall does with a command. Ordered from least to most restrictive."""

    ALLOW = "allow"
    WARN = "warn"
    CLAMP = "clamp"
    BLOCK = "block"

    @property
    def rank(self) -> int:
        return _ACTION_RANK[self]


_ACTION_RANK = {Action.ALLOW: 0, Action.WARN: 1, Action.CLAMP: 2, Action.BLOCK: 3}


class Category(str, Enum):
    THERMAL = "thermal"
    MOTION = "motion"
    FIRMWARE = "firmware"
    SABOTAGE = "sabotage"
    HOST = "host"
    POLICY = "policy"


@dataclass(frozen=True)
class Finding:
    """A single rule hit on a command (or on the stream as a whole)."""

    rule_id: str
    category: Category
    severity: Severity
    message: str
    line_no: int | None = None
    raw: str = ""
    clamp: Mapping[str, str] | None = None
    action: Action | None = None
    extra: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "rule": self.rule_id,
            "category": self.category.value,
            "severity": self.severity.value,
            "action": self.action.value if self.action else None,
            "message": self.message,
            "line": self.line_no,
            "raw": self.raw,
        }
        if self.clamp:
            out["clamp"] = dict(self.clamp)
        if self.extra:
            out["extra"] = dict(self.extra)
        return out
