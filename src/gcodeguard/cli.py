"""Command-line interface: ``gcodeguard scan|sanitize|simulate|profiles|rules|mcp|bench|audit``."""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from pathlib import Path

from gcodeguard import __version__
from gcodeguard.audit import AuditLog, verify
from gcodeguard.engine import Firewall
from gcodeguard.policy import PolicyError, builtin_profiles, load_policy
from gcodeguard.report import render_json, render_sarif, render_text, use_color

EXIT_OK, EXIT_WARN, EXIT_BLOCK, EXIT_ERROR = 0, 1, 2, 3


def _read_lines(path: str) -> list[str]:
    if path == "-":
        return sys.stdin.read().splitlines()
    file = Path(path)
    if not file.is_file():
        raise SystemExit(f"gcodeguard: {path}: no such file")
    return file.read_text(encoding="utf-8", errors="replace").splitlines()


def _policy(args: argparse.Namespace):
    refs = list(args.profile or []) + list(args.policy or [])
    if getattr(args, "strict", False):
        refs.append("agent-strict")
    policy = load_policy(*refs)
    if getattr(args, "monitor", False):
        from dataclasses import replace

        policy = replace(policy, mode="monitor")
    return policy


def _add_policy_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-p", "--profile", action="append", metavar="NAME",
                        help="built-in profile (repeatable; later ones override earlier ones)")
    parser.add_argument("--policy", action="append", metavar="FILE",
                        help="policy YAML file (repeatable, applied after --profile)")
    parser.add_argument("--strict", action="store_true",
                        help="add the agent-strict overlay (for untrusted/AI-generated G-code)")
    parser.add_argument("--monitor", action="store_true",
                        help="report what would be blocked, but never block")


# ----------------------------------------------------------------- commands
def cmd_scan(args: argparse.Namespace) -> int:
    firewall = Firewall(_policy(args))
    results = {path: firewall.scan(_read_lines(path)) for path in args.files}
    if args.format == "json":
        print(render_json(results))
    elif args.format == "sarif":
        print(render_sarif(results))
    else:
        color = use_color()
        print("\n\n".join(render_text(r, p, color, args.verbose) for p, r in results.items()))
    verdicts = {r.verdict for r in results.values()}
    if "block" in verdicts and args.fail_on in {"block", "warn"}:
        return EXIT_BLOCK
    if verdicts & {"warn", "clamp"} and args.fail_on == "warn":
        return EXIT_WARN
    return EXIT_OK


def cmd_sanitize(args: argparse.Namespace) -> int:
    firewall = Firewall(_policy(args))
    lines = _read_lines(args.file)
    out_lines = []
    blocked = rewritten = 0
    for text, decision in firewall.filter(lines):
        out_lines.append(text)
        blocked += decision.blocked
        rewritten += decision.rewritten
    stream = firewall.finish()
    payload = "\n".join(out_lines) + "\n"
    target = args.file if args.in_place else args.output
    if target in (None, "-"):
        sys.stdout.write(payload)
    else:
        _atomic_write(Path(target), payload)
    msg = f"gcodeguard: {blocked} blocked, {rewritten} rewritten, {len(stream)} end-of-file warnings"
    print(msg, file=sys.stderr)
    for finding in stream:
        print(f"gcodeguard: warning: {finding.message}", file=sys.stderr)
    return EXIT_BLOCK if blocked and args.fail_on_block else EXIT_OK


def _atomic_write(path: Path, payload: str) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(payload)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def cmd_simulate(args: argparse.Namespace) -> int:
    from gcodeguard.simulator import VirtualPrinter

    lines = _read_lines(args.file)
    printer = VirtualPrinter()
    blocked = 0
    if args.no_firewall:
        printer.run(lines)
    else:
        firewall = Firewall(_policy(args))
        for text, decision in firewall.filter(lines):
            blocked += decision.blocked
            printer.send(text)
    printer.finish()
    mode = "firmware only" if args.no_firewall else f"GcodeGuard ({blocked} blocked)"
    print(f"simulated {len(lines):,} lines in {printer.t / 60:.1f} min of printer time [{mode}]")
    peak = max((s[1] for s in printer.samples), default=printer.hw.ambient)
    print(f"peak hotend temperature: {peak:.0f}C")
    harms = printer.harms
    for event in printer.events:
        marker = "HARM" if event.harmful else "info"
        print(f"  [{marker}] t={event.t:>7.0f}s  {event.kind:<18} {event.message}")
    if not harms:
        print("  no harmful events")
    return EXIT_BLOCK if harms else EXIT_OK


def cmd_profiles(args: argparse.Namespace) -> int:
    for name in builtin_profiles():
        policy = load_policy(name) if name != "agent-strict" else None
        if policy is None:
            print(f"{name:<14} overlay for untrusted / AI-generated G-code")
            continue
        m = policy.machine
        vol = "x".join(f"{m.build_volume[a].high - m.build_volume[a].low:g}" for a in "XYZ")
        print(f"{name:<14} {m.firmware:<8} {vol:<12} hotend<={m.max_hotend_temp:g}C "
              f"bed<={m.max_bed_temp:g}C")
    return EXIT_OK


def cmd_rules(args: argparse.Namespace) -> int:
    from gcodeguard.rules import RULE_CLASSES

    for cls in RULE_CLASSES:
        print(f"{cls.id:<32} {cls.severity.value:<9} {cls.summary}")
    return EXIT_OK


def cmd_audit(args: argparse.Namespace) -> int:
    result = verify(args.file)
    if result.ok:
        print(f"ok: {result.records} records, hash chain intact")
        return EXIT_OK
    print(f"TAMPERED: {result.error} (after {result.records} valid records)")
    return EXIT_BLOCK


def cmd_klipper_path(args: argparse.Namespace) -> int:
    from gcodeguard.integrations import klipper_extra

    print(Path(klipper_extra.__file__).resolve())
    return EXIT_OK


def cmd_mcp(args: argparse.Namespace) -> int:
    from gcodeguard.mcp_server import serve

    audit = AuditLog(args.audit) if args.audit else None
    serve(backend=args.backend, url=args.url, api_key_env=args.api_key_env,
          policy=_policy(args), audit=audit)
    return EXIT_OK


def cmd_bench(args: argparse.Namespace) -> int:
    from gcodeguard.bench.cli import run

    return run(args)


# ------------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gcodeguard",
        description="Safety firewall for 3D printers: blocks dangerous, sabotaged, or "
                    "AI-injected G-code before it reaches the machine.",
    )
    parser.add_argument("--version", action="version", version=f"gcodeguard {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan G-code files and report findings")
    scan.add_argument("files", nargs="+", help="G-code files ('-' for stdin)")
    scan.add_argument("-f", "--format", choices=["text", "json", "sarif"], default="text")
    scan.add_argument("--fail-on", choices=["block", "warn", "never"], default="block")
    scan.add_argument("-v", "--verbose", action="store_true", help="include info findings")
    _add_policy_args(scan)
    scan.set_defaults(func=cmd_scan)

    san = sub.add_parser("sanitize", help="comment out blocked lines (slicer post-processing)")
    san.add_argument("file")
    group = san.add_mutually_exclusive_group()
    group.add_argument("-o", "--output", help="output path (default stdout)")
    group.add_argument("-i", "--in-place", action="store_true", help="rewrite the file in place")
    san.add_argument("--fail-on-block", action="store_true",
                     help="exit 2 if anything was blocked (makes the slicer show an error)")
    _add_policy_args(san)
    san.set_defaults(func=cmd_sanitize)

    sim = sub.add_parser("simulate", help="run G-code on a virtual printer and report hazards")
    sim.add_argument("file")
    sim.add_argument("--no-firewall", action="store_true", help="firmware protections only")
    _add_policy_args(sim)
    sim.set_defaults(func=cmd_simulate)

    sub.add_parser("profiles", help="list built-in machine profiles").set_defaults(func=cmd_profiles)
    sub.add_parser("rules", help="list detection rules").set_defaults(func=cmd_rules)
    sub.add_parser("klipper-path", help="print the Klipper extras module path (for ln -s)"
                   ).set_defaults(func=cmd_klipper_path)

    audit = sub.add_parser("audit", help="verify a hash-chained audit log")
    audit.add_argument("action", choices=["verify"])
    audit.add_argument("file")
    audit.set_defaults(func=cmd_audit)

    mcp = sub.add_parser("mcp", help="run the guarded MCP server for AI agents (stdio)")
    mcp.add_argument("--backend", choices=["sim", "octoprint", "moonraker"], default="sim")
    mcp.add_argument("--url", help="OctoPrint/Moonraker base URL, e.g. http://octopi.local")
    mcp.add_argument("--api-key-env", default="GCODEGUARD_PRINTER_API_KEY",
                     help="environment variable holding the printer API key")
    mcp.add_argument("--audit", metavar="FILE", help="append decisions to this audit log")
    _add_policy_args(mcp)
    mcp.set_defaults(func=cmd_mcp)

    from gcodeguard.bench.cli import add_parser as add_bench

    add_bench(sub)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except PolicyError as exc:
        print(f"gcodeguard: policy error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except BrokenPipeError:
        return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
