"""The firewall engine: parse -> evaluate rules -> resolve an action -> update state."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from typing import Protocol

from gcodeguard.commands import SAFETY_COMMANDS
from gcodeguard.gcode import Command, parse_line
from gcodeguard.model import Action, Finding, Severity
from gcodeguard.policy import Policy, load_policy
from gcodeguard.rules import Context, Rule, default_rules
from gcodeguard.state import MachineState


class AuditSink(Protocol):
    def record(self, event: str, payload: dict) -> None: ...


@dataclass(frozen=True)
class Decision:
    command: Command
    action: Action
    findings: tuple[Finding, ...] = ()
    output: str | None = None  # what to forward to the printer; None when blocked
    would_block: bool = False  # monitor mode: what enforce mode would have done

    @property
    def blocked(self) -> bool:
        return self.action is Action.BLOCK

    @property
    def rewritten(self) -> bool:
        return self.action is Action.CLAMP

    def to_dict(self) -> dict:
        return {
            "line": self.command.line_no,
            "raw": self.command.raw.strip(),
            "action": self.action.value,
            "output": self.output,
            "would_block": self.would_block,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class ScanResult:
    policy: str
    decisions: list[Decision] = field(default_factory=list)  # only lines with findings
    stream_findings: list[Finding] = field(default_factory=list)
    lines: int = 0
    actions: Counter = field(default_factory=Counter)

    @property
    def findings(self) -> list[Finding]:
        out = [f for d in self.decisions for f in d.findings]
        return out + self.stream_findings

    @property
    def verdict(self) -> str:
        if self.actions[Action.BLOCK] or any(d.would_block for d in self.decisions):
            return "block"
        if self.actions[Action.CLAMP]:
            return "clamp"
        if any(f.severity is not Severity.INFO for f in self.findings):
            return "warn"
        return "pass"

    def to_dict(self) -> dict:
        return {
            "policy": self.policy,
            "verdict": self.verdict,
            "lines": self.lines,
            "actions": {a.value: self.actions.get(a, 0) for a in Action},
            "decisions": [d.to_dict() for d in self.decisions],
            "stream_findings": [f.to_dict() for f in self.stream_findings],
        }


class Firewall:
    """Stateful G-code firewall. One instance per command stream (per printer)."""

    def __init__(
        self,
        policy: Policy | None = None,
        rules: Iterable[Rule] | None = None,
        audit: AuditSink | None = None,
    ) -> None:
        self.policy = policy or load_policy()
        self.rules = [
            r for r in (list(rules) if rules is not None else default_rules())
            if self.policy.rule(r.id).enabled
        ]
        self.audit = audit
        self.state = MachineState()
        self.counts: Counter = Counter()
        self._line_no = 0

    # ----------------------------------------------------------------- API
    def reset(self) -> None:
        self.state = MachineState()
        self.counts.clear()
        self._line_no = 0
        for rule in self.rules:
            rule.reset()

    def check(self, line: str | Command, line_no: int | None = None) -> Decision:
        """Decide what to do with one line, and advance state if it is forwarded."""
        self._line_no += 1
        cmd = line if isinstance(line, Command) else parse_line(line, line_no or self._line_no)
        if cmd.is_empty:
            return Decision(cmd, Action.ALLOW, output=cmd.raw)

        motion = self.state.project(cmd)
        ctx = Context(cmd, self.state, motion, self.policy)
        findings: list[Finding] = []
        if cmd.code not in SAFETY_COMMANDS:
            for rule in self.rules:
                findings.extend(self._resolve(f) for f in rule.check(ctx))

        decision = self._decide(cmd, findings)
        if decision.output is not None:
            out_cmd = parse_line(decision.output, cmd.line_no) if decision.rewritten else cmd
            self.state.apply(out_cmd, self.state.project(out_cmd))
        self.counts[decision.action] += 1
        if self.audit is not None and decision.findings:
            self.audit.record("decision", decision.to_dict())
        return decision

    def finish(self) -> list[Finding]:
        """End-of-stream checks (heaters left on, last layer anomalies, ...)."""
        out: list[Finding] = []
        for rule in self.rules:
            out.extend(self._resolve(f) for f in rule.finish(self.state, self.policy))
        if self.audit is not None and out:
            self.audit.record("stream", {"findings": [f.to_dict() for f in out]})
        return out

    def scan(self, lines: Iterable[str]) -> ScanResult:
        """Scan a whole file from a fresh state."""
        self.reset()
        result = ScanResult(policy=self.policy.name)
        for number, line in enumerate(lines, start=1):
            decision = self.check(line, number)
            result.lines = number
            result.actions[decision.action] += 1
            if decision.findings:
                result.decisions.append(decision)
        result.stream_findings = self.finish()
        return result

    def filter(self, lines: Iterable[str], epilogue: bool = True) -> Iterable[tuple[str, Decision]]:
        """Yield sanitised output lines (blocked lines become comments).

        With ``epilogue`` (the default) a stream that ends with heaters still on
        gets heater-off commands appended, so a blocked or missing end sequence
        can't leave the printer sitting hot and unattended.
        """
        for line in lines:
            decision = self.check(line)
            if decision.output is None:
                reasons = "; ".join(f.message for f in decision.findings)
                yield f"; GCODEGUARD BLOCKED: {decision.command.raw.strip()} ({reasons})", decision
            else:
                yield decision.output, decision
        if epilogue and self.policy.enforcing:
            for line in self.cooldown_lines():
                yield line, self.check(line)

    def cooldown_lines(self) -> list[str]:
        """Commands that switch off every heater the state believes is on."""
        out = []
        threshold = self.policy.thermal.idle_heater_threshold_c
        for tool, target in sorted(self.state.hotend_target.items()):
            if target > threshold:
                out.append(f"M104 S0 T{tool} ; GCODEGUARD: heaters left on, cooling down")
        if self.state.bed_target > threshold:
            out.append("M140 S0 ; GCODEGUARD: heaters left on, cooling down")
        if self.state.chamber_target > threshold:
            out.append("M141 S0 ; GCODEGUARD: heaters left on, cooling down")
        return out

    # ------------------------------------------------------------ internals
    def _resolve(self, finding: Finding) -> Finding:
        cfg = self.policy.rule(finding.rule_id)
        severity = cfg.severity or finding.severity
        action = cfg.action or finding.action or self.policy.actions[severity]
        if action is Action.CLAMP and not finding.clamp:
            action = Action.BLOCK
        return replace(finding, severity=severity, action=action)

    def _decide(self, cmd: Command, findings: list[Finding]) -> Decision:
        if not findings:
            return Decision(cmd, Action.ALLOW, output=cmd.raw)
        action = max((f.action for f in findings), key=lambda a: a.rank)
        output: str | None = cmd.raw
        if action is Action.CLAMP:
            updates: dict[str, str] = {}
            for f in findings:
                if f.action is Action.CLAMP and f.clamp:
                    updates.update(f.clamp)
            output = cmd.with_params(updates).to_line()
        elif action is Action.BLOCK:
            output = None
        if not self.policy.enforcing and action in (Action.BLOCK, Action.CLAMP):
            return Decision(cmd, Action.WARN, tuple(findings), cmd.raw, would_block=True)
        return Decision(cmd, action, tuple(findings), output)
