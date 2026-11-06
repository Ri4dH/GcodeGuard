"""Corpus benchmark: detection, prevention, and false positives, measured on a simulator."""

from __future__ import annotations

from dataclasses import dataclass, field

from gcodeguard.bench.corpus import ATTACKS, Attack, build, generate, random_spec
from gcodeguard.engine import Firewall
from gcodeguard.guarded import GATE_WARNING_CATEGORIES
from gcodeguard.model import Action, Severity
from gcodeguard.policy import Policy, load_policy
from gcodeguard.simulator import VirtualPrinter


@dataclass
class AttackResult:
    attack: Attack
    trials: int = 0
    detected: int = 0
    blocked: int = 0
    harm_firmware: int = 0
    harm_guarded: int = 0
    gate_refused: int = 0
    harm_gated: int = 0
    harm_kinds: set[str] = field(default_factory=set)


@dataclass
class BenignResult:
    files: int = 0
    lines: int = 0
    files_warned: int = 0
    files_blocked: int = 0
    rules_hit: dict[str, int] = field(default_factory=dict)
    harm: int = 0


@dataclass
class CorpusReport:
    policy: str
    attacks: list[AttackResult]
    benign: BenignResult

    def to_dict(self) -> dict:
        return {
            "policy": self.policy,
            "benign": {
                "files": self.benign.files,
                "lines": self.benign.lines,
                "false_positive_warn_rate": _rate(self.benign.files_warned, self.benign.files),
                "false_positive_block_rate": _rate(self.benign.files_blocked, self.benign.files),
                "rules_hit": self.benign.rules_hit,
            },
            "attacks": [
                {
                    "id": r.attack.id,
                    "category": r.attack.category,
                    "trials": r.trials,
                    "detection_rate": _rate(r.detected, r.trials),
                    "block_rate": _rate(r.blocked, r.trials),
                    "harm_rate_firmware_only": _rate(r.harm_firmware, r.trials),
                    "harm_rate_with_gcodeguard": _rate(r.harm_guarded, r.trials),
                    "preprint_gate_refusal_rate": _rate(r.gate_refused, r.trials),
                    "harm_rate_with_preprint_gate": _rate(r.harm_gated, r.trials),
                    "harm_kinds": sorted(r.harm_kinds),
                }
                for r in self.attacks
            ],
        }


def _rate(n: int, d: int) -> float:
    return round(n / d, 4) if d else 0.0


def _simulate(lines: list[str], firewall: Firewall | None) -> VirtualPrinter:
    printer = VirtualPrinter()
    if firewall is None:
        printer.run(lines)
    else:
        firewall.reset()
        for text, _ in firewall.filter(lines):
            printer.send(text)
    printer.finish()
    return printer


def run_corpus(
    policy: Policy | None = None,
    seeds: range = range(1, 21),
    attacks: tuple[Attack, ...] = ATTACKS,
    simulate: bool = True,
) -> CorpusReport:
    policy = policy or load_policy("ender3")
    firewall = Firewall(policy)
    benign = BenignResult()
    specs = [random_spec(seed) for seed in seeds]

    for spec in specs:
        lines = generate(spec)
        result = firewall.scan(lines)
        benign.files += 1
        benign.lines += len(lines)
        relevant = [f for f in result.findings if f.severity is not Severity.INFO]
        if any(f.action in (Action.WARN, Action.CLAMP, Action.BLOCK) for f in relevant):
            benign.files_warned += 1
        if result.verdict == "block":
            benign.files_blocked += 1
        for finding in relevant:
            benign.rules_hit[finding.rule_id] = benign.rules_hit.get(finding.rule_id, 0) + 1
        if simulate and _simulate(lines, None).harms:
            benign.harm += 1

    results = []
    for attack in attacks:
        ar = AttackResult(attack)
        for spec in specs:
            lines = build(attack, spec)
            scan = firewall.scan(lines)
            hits = [f for f in scan.findings
                    if f.rule_id in attack.expected_rules and f.severity is not Severity.INFO]
            ar.trials += 1
            ar.detected += bool(hits)
            ar.blocked += any(f.action is Action.BLOCK for f in hits)
            refused = any(
                f.action is Action.BLOCK
                or (f.action is Action.WARN and f.category in GATE_WARNING_CATEGORIES)
                for f in scan.findings if f.severity is not Severity.INFO
            )
            ar.gate_refused += refused
            if simulate:
                raw = _simulate(lines, None)
                guarded = _simulate(lines, firewall)
                ar.harm_firmware += bool(raw.harms)
                ar.harm_guarded += bool(guarded.harms)
                ar.harm_gated += bool(guarded.harms) and not refused
                ar.harm_kinds |= raw.harm_kinds()
        results.append(ar)
    return CorpusReport(policy.name, results, benign)


def render_markdown(report: CorpusReport) -> str:
    def pct(n: int, d: int) -> str:
        return f"{100 * n / d:.0f}%" if d else "-"

    b = report.benign
    rows = [
        f"Policy `{report.policy}`, {len(report.attacks)} attack classes x "
        f"{report.attacks[0].trials if report.attacks else 0} generated prints each, "
        f"plus {b.files} benign prints ({b.lines:,} lines).",
        "",
        "| Attack | Category | Detected | Harm: firmware only | Harm: GcodeGuard streaming | "
        "Harm: GcodeGuard pre-print gate |",
        "|---|---|---:|---:|---:|---:|",
    ]
    for r in report.attacks:
        name = r.attack.id + (" (stealthy)" if r.attack.stealthy else "")
        rows.append(
            f"| `{name}` | {r.attack.category} | {pct(r.detected, r.trials)} | "
            f"{pct(r.harm_firmware, r.trials)} | {pct(r.harm_guarded, r.trials)} | "
            f"{pct(r.harm_gated, r.trials)} |"
        )
    rows += [
        "",
        f"Benign prints: {pct(b.files_warned, b.files)} raised any warning, "
        f"{pct(b.files_blocked, b.files)} had anything blocked, "
        f"{pct(b.harm, b.files)} caused simulated harm.",
    ]
    if b.rules_hit:
        hits = ", ".join(f"`{k}` x{v}" for k, v in sorted(b.rules_hit.items()))
        rows.append(f"Benign warnings came from: {hits}.")
    return "\n".join(rows)
