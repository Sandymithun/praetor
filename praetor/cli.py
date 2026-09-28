"""Command line interface: point it at a file of events, get readable alerts."""

import sys
from collections import Counter
from pathlib import Path

from .alert import Alert
from .events import read_jsonl
from .ingest import parse_event

USAGE = "usage: python -m praetor <events.jsonl>"


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


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print(USAGE, file=sys.stderr)
        return 2

    path = Path(argv[0])
    if not path.exists():
        print(f"error: no such file: {path}", file=sys.stderr)
        return 1

    result = read_jsonl(path)
    alerts = [parse_event(event) for event in result.events]

    for alert in sorted(alerts, key=lambda a: -a.severity.value):
        print(format_alert(alert))

    print()
    print(result.summary())
    print(summarise(alerts))
    return 0
