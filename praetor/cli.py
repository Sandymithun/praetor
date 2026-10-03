"""Command line interface: point it at a file of events, get answers.

Two modes.

    python -m praetor samples/mixed.jsonl
        Normalise and list. What Week 1 built.

    python -m praetor --triage samples/mixed.jsonl
        The full pipeline: deduplicate, enrich, score, propose actions.

The default stays the harmless one. Running the thing that can block
addresses should take an extra word on the command line.
"""

import argparse
import sys
from collections import Counter
from pathlib import Path

from .actions import Responder
from .alert import Alert
from .enrich import default_enricher
from .events import read_jsonl
from .ingest import parse_event
from .pipeline import Pipeline
from .scoring import RiskScore, Scorer

USAGE = "usage: python -m praetor [--triage] [--offline] <events.jsonl>"


# --------------------------------------------------------------------------- #
# Week 1 output
# --------------------------------------------------------------------------- #

def format_alert(alert: Alert) -> str:
    """One readable line per alert."""
    host = alert.host or "-"
    return (f"[{alert.severity.label:>8}] {alert.timestamp:%H:%M:%S} "
            f"{alert.source:<10} {host:<16} {alert.title}")


def summarise(alerts: list[Alert]) -> str:
    """The bit a human reads after the list scrolls past."""
    if not alerts:
        return "No alerts."

    by_severity = Counter(a.severity.label for a in alerts)
    by_source = Counter(a.source for a in alerts)
    unmapped = sum(1 for a in alerts if "unmapped" in a.tags)

    order = ["critical", "high", "medium", "low", "info"]
    counts = "  ".join(f"{name}={by_severity[name]}" for name in order if by_severity[name])
    sources = ", ".join(f"{name} ({n})" for name, n in by_source.most_common())

    lines = [
        f"{len(alerts)} alert(s)",
        f"  severity : {counts}",
        f"  sensors  : {sources}",
        f"  unmapped : {unmapped}"
        + ("   <-- check these; a parser may have stopped matching" if unmapped else ""),
    ]
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Week 4 output
# --------------------------------------------------------------------------- #

def format_case(score: RiskScore, outcomes: list) -> str:
    """One triaged case: the alert, the score, the working, the actions."""
    alert = score.alert
    lines = [
        f"{'=' * 72}",
        f"[{alert.severity.label:>8}] {alert.source:<10} {alert.host or '-':<16} {alert.title}",
        "",
        score.explain(),
    ]
    if outcomes:
        lines.append("")
        for outcome in outcomes:
            lines.append(f"  {outcome}")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m praetor",
        description="Normalise, triage and respond to security alerts.",
    )
    parser.add_argument("path", help="a JSON-Lines file of sensor events")
    parser.add_argument("--triage", action="store_true",
                        help="run the full pipeline instead of just listing")
    parser.add_argument("--offline", action="store_true",
                        help="never call a real intelligence provider")
    parser.add_argument("--min-score", type=int, default=0,
                        help="only show cases at or above this risk score")
    parser.add_argument("--allow-disruptive", action="store_true",
                        help="permit blocking and isolation to be proposed and guarded")
    parser.add_argument("--arm", action="store_true",
                        help="ACTUALLY PERFORM actions instead of dry-running them")
    return parser


def run_triage(path: Path, args: argparse.Namespace) -> int:
    pipeline = Pipeline(
        enricher=default_enricher(offline=args.offline),
        scorer=Scorer(),
        responder=Responder(
            dry_run=not args.arm,
            allow_disruptive=args.allow_disruptive,
        ),
    )

    if args.arm:
        print("!! ARMED: actions will be performed for real.\n", file=sys.stderr)

    result = read_jsonl(path)
    triage = pipeline.run(result.events)

    shown = 0
    for score in triage.scores:
        if score.value < args.min_score:
            continue
        print(format_case(score, triage.outcomes_for(score)))
        shown += 1

    print()
    print(triage.summary())
    print(pipeline.responder.audit_summary())
    if shown == 0:
        print(f"  (nothing at or above score {args.min_score})")
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print(USAGE, file=sys.stderr)
        return 2

    args = build_parser().parse_args(argv)

    path = Path(args.path)
    if not path.exists():
        print(f"error: no such file: {path}", file=sys.stderr)
        return 1

    if args.triage:
        return run_triage(path, args)

    result = read_jsonl(path)
    alerts = [parse_event(event) for event in result.events]

    for alert in sorted(alerts, key=lambda a: -a.severity.value):
        print(format_alert(alert))

    print()
    print(result.summary())
    print(summarise(alerts))
    return 0
