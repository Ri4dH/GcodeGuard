"""GuardedPrinter: every path from a controller to a printer goes through the firewall.

* Live commands are filtered line by line with a persistent firewall state.
* Files are scanned in full *before* printing (the pre-print gate). A file with
  blocked commands, or with sabotage warnings, is refused, because once a host
  like OctoPrint streams it the agent can no longer intervene.
* A heater watchdog switches heaters off when nothing has happened for a while.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from gcodeguard.backends.base import BackendError, PrinterBackend, validate_filename
from gcodeguard.engine import AuditSink, Firewall, ScanResult
from gcodeguard.model import Action, Category, Finding, Severity
from gcodeguard.policy import Policy

GATE_WARNING_CATEGORIES = frozenset({Category.SABOTAGE})
_PRINTING_STATES = {"printing", "paused", "printing from sd", "pausing"}


@dataclass
class LiveResult:
    sent: list[str] = field(default_factory=list)
    rewritten: list[tuple[str, str]] = field(default_factory=list)
    blocked: list[tuple[str, list[Finding]]] = field(default_factory=list)
    warnings: list[Finding] = field(default_factory=list)
    responses: list[str] = field(default_factory=list)


@dataclass
class GateResult:
    allowed: bool
    scan: ScanResult
    reasons: list[Finding] = field(default_factory=list)
    printed_as: str | None = None


class GuardedPrinter:
    def __init__(
        self,
        backend: PrinterBackend,
        policy: Policy,
        audit: AuditSink | None = None,
        clock: Callable[[], float] = time.monotonic,
        gate_warning_categories: frozenset[Category] = GATE_WARNING_CATEGORIES,
    ) -> None:
        self.backend = backend
        self.policy = policy
        self.audit = audit
        self.clock = clock
        self.live = Firewall(policy, audit=audit)
        self.gate_warning_categories = gate_warning_categories
        self.events: deque[dict[str, Any]] = deque(maxlen=200)
        self.last_activity = clock()
        self._lock = threading.RLock()

    # ------------------------------------------------------------ helpers
    def _log(self, kind: str, **data: Any) -> None:
        event = {"t": round(self.clock(), 1), "event": kind, **data}
        self.events.append(event)
        if self.audit is not None:
            self.audit.record(kind, data)

    def _printing(self) -> bool | None:
        try:
            state = str(self.backend.status().get("state", "")).lower()
        except BackendError:
            return None
        return state in _PRINTING_STATES

    # --------------------------------------------------------------- live
    def send_gcode(self, text: str, source: str = "agent") -> LiveResult:
        result = LiveResult()
        with self._lock:
            self.live.state.printing_override = self._printing()
            for line in text.replace("\\n", "\n").splitlines():
                decision = self.live.check(line)
                if decision.command.is_empty:
                    continue
                result.warnings.extend(f for f in decision.findings if f.action is Action.WARN)
                if decision.output is None:
                    result.blocked.append((line.strip(), list(decision.findings)))
                    self._log("blocked", source=source, line=line.strip(),
                              rules=[f.rule_id for f in decision.findings])
                    continue
                if decision.rewritten:
                    result.rewritten.append((line.strip(), decision.output))
                result.sent.append(decision.output)
            if result.sent:
                result.responses = self.backend.send_gcode(result.sent)
                self.last_activity = self.clock()
        return result

    # --------------------------------------------------------------- files
    def scan_file(self, content: str) -> ScanResult:
        return Firewall(self.policy).scan(content.splitlines())

    def gate(self, content: str) -> GateResult:
        scan = self.scan_file(content)
        reasons = [f for f in scan.findings if f.action is Action.BLOCK]
        reasons += [
            f for f in scan.findings
            if f.action is Action.WARN and f.category in self.gate_warning_categories
            and f.severity is not Severity.INFO
        ]
        if not self.policy.enforcing:  # monitor mode reports but never refuses
            return GateResult(allowed=True, scan=scan, reasons=reasons)
        return GateResult(allowed=not reasons, scan=scan, reasons=reasons)

    def print_file(self, name: str, source: str = "agent") -> GateResult:
        name = validate_filename(name)
        content = self.backend.read_file(name)
        return self._print_content(name, content, source, upload_original=False)

    def upload_and_print(self, name: str, content: str, source: str = "agent") -> GateResult:
        name = validate_filename(name)
        return self._print_content(name, content, source, upload_original=True)

    def _print_content(self, name: str, content: str, source: str, upload_original: bool) -> GateResult:
        with self._lock:
            result = self.gate(content)
            if not result.allowed:
                self._log("print_refused", source=source, file=name,
                          rules=sorted({f.rule_id for f in result.reasons}))
                return result
            firewall = Firewall(self.policy)
            sanitized = [text for text, _ in firewall.filter(content.splitlines())]
            changed = sanitized != content.splitlines()
            target = name
            if changed:
                target = f"gcodeguard-{name}"
                self.backend.upload(target, "\n".join(sanitized) + "\n")
            elif upload_original:
                self.backend.upload(name, content)
            self.backend.start_print(target)
            self.last_activity = self.clock()
            result.printed_as = target
            self._log("print_started", source=source, file=name, printed_as=target)
            return result

    # ------------------------------------------------------------ watchdog
    def watchdog_tick(self) -> str | None:
        """Switch heaters off if they've been on with nothing happening. Returns a message if so."""
        timeout = self.policy.thermal.heater_idle_timeout_s
        try:
            status = self.backend.status()
        except BackendError:
            return None
        if str(status.get("state", "")).lower() in _PRINTING_STATES:
            self.last_activity = self.clock()
            return None
        threshold = self.policy.thermal.idle_heater_threshold_c
        targets = [(status.get(h) or {}).get("target") or 0 for h in ("hotend", "bed")]
        if max(targets) <= threshold:
            return None
        idle = self.clock() - self.last_activity
        if idle < timeout:
            return None
        self.backend.send_gcode(["M104 S0", "M140 S0"])
        self.live.state.hotend_target.clear()
        self.live.state.bed_target = 0.0
        message = f"heaters were on and idle for {idle / 60:.0f} min; switched them off"
        self._log("watchdog_cooldown", idle_s=round(idle), targets=targets)
        return message

    def start_watchdog(self, interval_s: float = 30.0) -> threading.Event:
        stop = threading.Event()

        def loop() -> None:
            while not stop.wait(interval_s):
                self.watchdog_tick()

        threading.Thread(target=loop, name="gcodeguard-watchdog", daemon=True).start()
        return stop
