"""Rule interface."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from gcodeguard.gcode import Command
from gcodeguard.model import Action, Category, Finding, Severity
from gcodeguard.policy import Policy
from gcodeguard.state import MachineState, Motion


@dataclass(frozen=True)
class Context:
    cmd: Command
    state: MachineState  # state *before* the command runs
    motion: Motion | None
    policy: Policy


class Rule:
    """Base class. Subclasses set the class attributes and override ``check``/``finish``."""

    id: str = ""
    category: Category = Category.POLICY
    severity: Severity = Severity.WARNING
    summary: str = ""

    def check(self, ctx: Context) -> Iterable[Finding]:
        return ()

    def finish(self, state: MachineState, policy: Policy) -> Iterable[Finding]:
        """Called once at end of stream (file scans) for whole-stream checks."""
        return ()

    def reset(self) -> None:
        """Forget any per-stream memory."""

    def hit(
        self,
        ctx: Context | None,
        message: str,
        severity: Severity | None = None,
        clamp: Mapping[str, str] | None = None,
        action: Action | None = None,
        **extra: object,
    ) -> Finding:
        cmd = ctx.cmd if ctx else None
        return Finding(
            rule_id=self.id,
            category=self.category,
            severity=severity or self.severity,
            message=message,
            line_no=cmd.line_no if cmd else None,
            raw=cmd.raw.strip() if cmd else "",
            clamp=clamp,
            action=action,
            extra=extra,
        )


def fmt(value: float) -> str:
    """Compact number formatting for messages and rewritten commands."""
    return f"{value:.0f}" if float(value).is_integer() else f"{value:g}"
