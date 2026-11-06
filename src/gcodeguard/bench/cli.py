"""``gcodeguard bench corpus|agent`` subcommands."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def add_parser(sub) -> None:
    bench = sub.add_parser("bench", help="run the attack benchmark")
    bsub = bench.add_subparsers(dest="bench_command", required=True)

    corpus = bsub.add_parser("corpus", help="G-code attack corpus vs. firmware-only baseline")
    corpus.add_argument("--seeds", type=int, default=20, help="generated prints per attack")
    corpus.add_argument("--profile", default="ender3")
    corpus.add_argument("--no-sim", action="store_true", help="skip physical simulation")
    corpus.add_argument("--json", metavar="FILE", help="also write raw results as JSON")

    agent = bsub.add_parser("agent", help="prompt-injection scenarios against an LLM agent")
    agent.add_argument("--agent", choices=["scripted", "claude"], default="scripted",
                       help="'scripted' = worst-case agent that obeys every injection; "
                            "'claude' = a real Claude model via the Anthropic API")
    agent.add_argument("--model", default="claude-opus-5-5")
    agent.add_argument("--effort", default="medium", choices=["low", "medium", "high", "xhigh", "max"])
    agent.add_argument("--scenario", action="append", help="run only these scenario ids")
    agent.add_argument("--repeats", type=int, default=1)
    agent.add_argument("--json", metavar="FILE", help="also write transcripts and results as JSON")
    bench.set_defaults(func=run)


def run(args: argparse.Namespace) -> int:
    if args.bench_command == "corpus":
        from gcodeguard.bench.runner import render_markdown, run_corpus
        from gcodeguard.policy import load_policy

        report = run_corpus(load_policy(args.profile), seeds=range(1, args.seeds + 1),
                            simulate=not args.no_sim)
        print(render_markdown(report))
        if args.json:
            Path(args.json).write_text(json.dumps(report.to_dict(), indent=2))
        return 0

    from gcodeguard.bench.agent import render_markdown, run_agent_bench

    results = run_agent_bench(agent=args.agent, model=args.model, effort=args.effort,
                              only=args.scenario, repeats=args.repeats, log=sys.stderr)
    print(render_markdown(results))
    if args.json:
        Path(args.json).write_text(json.dumps([r.to_dict() for r in results], indent=2))
    return 0
