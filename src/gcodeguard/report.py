"""Render scan results as coloured text, JSON, or SARIF (GitHub code scanning)."""

from __future__ import annotations

import json
import os
import sys

from gcodeguard import __version__
from gcodeguard.engine import ScanResult
from gcodeguard.model import Action, Finding, Severity
from gcodeguard.rules import RULE_CLASSES

_COLORS = {
    "block": "\033[1;37;41m",
    "clamp": "\033[1;30;43m",
    "warn": "\033[1;30;43m",
    "allow": "\033[2m",
    "pass": "\033[1;30;42m",
    "dim": "\033[2m",
    "bold": "\033[1m",
    "red": "\033[31m",
    "yellow": "\033[33m",
    "green": "\033[32m",
    "cyan": "\033[36m",
    "reset": "\033[0m",
}


def use_color(stream=None) -> bool:
    stream = stream or sys.stdout
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return hasattr(stream, "isatty") and stream.isatty()


class Painter:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def __call__(self, style: str, text: str) -> str:
        if not self.enabled:
            return text
        return f"{_COLORS[style]}{text}{_COLORS['reset']}"


def _label(action: Action | None, would_block: bool) -> str:
    if would_block:
        return "would-block"
    return (action or Action.ALLOW).value


def render_text(result: ScanResult, path: str, color: bool = False, verbose: bool = False) -> str:
    p = Painter(color)
    out = [f"{p('bold', 'GcodeGuard')} {p('cyan', path)} {p('dim', f'(policy: {result.policy})')}"]
    shown = 0
    for decision in result.decisions:
        visible = [f for f in decision.findings if verbose or f.severity is not Severity.INFO]
        if not visible:
            continue
        label = _label(decision.action, decision.would_block)
        style = "block" if label in {"block", "would-block"} else (
            "clamp" if label == "clamp" else ("warn" if label == "warn" else "allow")
        )
        for finding in visible:
            shown += 1
            line = f"L{finding.line_no}" if finding.line_no else "  -"
            out.append(
                f"  {p(style, f' {label.upper():<5} ')} {p('dim', f'{line:>7}')}  "
                f"{finding.raw[:38]:<38}  {p('yellow', finding.rule_id)}"
            )
            out.append(f"  {'':7}  {'':7}  {p('dim', '-> ' + finding.message)}")
            if decision.rewritten and decision.output:
                out.append(f"  {'':7}  {'':7}  {p('green', 'rewritten: ' + decision.output)}")
    for finding in result.stream_findings:
        if not verbose and finding.severity is Severity.INFO:
            continue
        shown += 1
        out.append(f"  {p('warn', ' WARN  ')} {p('dim', '    eof')}  {'':38}  "
                   f"{p('yellow', finding.rule_id)}")
        out.append(f"  {'':7}  {'':7}  {p('dim', '-> ' + finding.message)}")
    verdict = result.verdict
    v_style = {"block": "block", "clamp": "clamp", "warn": "warn", "pass": "pass"}[verdict]
    counts = result.actions
    summary = (
        f"{result.lines:,} lines, {counts[Action.BLOCK]} blocked, {counts[Action.CLAMP]} rewritten, "
        f"{sum(1 for f in result.findings if f.action is Action.WARN)} warnings"
    )
    if shown == 0:
        out.append(f"  {p('green', 'no findings')}")
    out.append(f"  {p(v_style, f' {verdict.upper()} ')} {p('dim', summary)}")
    return "\n".join(out)


def render_json(results: dict[str, ScanResult]) -> str:
    return json.dumps({path: r.to_dict() for path, r in results.items()}, indent=2)


_SARIF_LEVEL = {Severity.CRITICAL: "error", Severity.WARNING: "warning", Severity.INFO: "note"}


def _sarif_result(path: str, finding: Finding) -> dict:
    location = {"artifactLocation": {"uri": path}}
    if finding.line_no:
        location["region"] = {"startLine": finding.line_no}
    return {
        "ruleId": finding.rule_id,
        "level": _SARIF_LEVEL[finding.severity],
        "message": {"text": f"{finding.message} [{finding.raw}]".strip()},
        "locations": [{"physicalLocation": location}],
    }


def render_sarif(results: dict[str, ScanResult]) -> str:
    rules = [
        {"id": cls.id, "shortDescription": {"text": cls.summary},
         "defaultConfiguration": {"level": _SARIF_LEVEL[cls.severity]}}
        for cls in RULE_CLASSES
    ]
    sarif_results = [
        _sarif_result(path, f) for path, result in results.items() for f in result.findings
    ]
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "GcodeGuard",
                "version": __version__,
                "informationUri": "https://github.com/Ri4dH/PrintGuard",
                "rules": rules,
            }},
            "results": sarif_results,
        }],
    }
    return json.dumps(doc, indent=2)
