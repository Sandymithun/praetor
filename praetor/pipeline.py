"""The whole thing, in order.

Weeks 1-4 each built one stage. This file is the only place that knows what
order they go in, and reading it top to bottom is the fastest way to
understand the program:

    parse -> deduplicate -> enrich -> score -> respond

The single most important line in this file is that deduplication happens
*before* enrichment. Reverse those two and a 5,000-event brute-force burst
costs 5,000 API calls to learn one fact -- the day's entire intelligence
budget, gone in ninety seconds, to answer a question you already answered.

Cheap filters before expensive work. That ordering is the difference between
a system that runs all day and one that runs until 09:02.
"""

from dataclasses import dataclass, field

from .actions import Outcome, Responder
from .alert import Alert
from .dedupe import Deduplicator
from .enrich import EnrichmentReport, Enricher, default_enricher
from .ingest import parse_event
from .scoring import RiskScore, Scorer


@dataclass
class TriageResult:
    """Everything one run produced."""

    scores: list[RiskScore] = field(default_factory=list)
    reports: dict[str, EnrichmentReport] = field(default_factory=dict)
    outcomes: dict[str, list[Outcome]] = field(default_factory=dict)

    events_read: int = 0
    alerts_parsed: int = 0
    suppressed: int = 0

    @property
    def triaged(self) -> int:
        return len(self.scores)

    def outcomes_for(self, score: RiskScore) -> list[Outcome]:
        return self.outcomes.get(score.alert.fingerprint(), [])

    def summary(self) -> str:
        lookups = sum(len(r.results) for r in self.reports.values())
        failed = sum(len(r.errors) for r in self.reports.values())
        lines = [
            f"{self.events_read} event(s) -> {self.alerts_parsed} alert(s) "
            f"-> {self.triaged} case(s)",
            f"  suppressed : {self.suppressed} duplicate(s)",
            f"  lookups    : {lookups}"
            + (f"   ({failed} failed -- scores below are partial)" if failed else ""),
        ]
        return "\n".join(lines)


@dataclass
class Pipeline:
    """Holds the four stages and runs events through them."""

    deduplicator: Deduplicator = field(default_factory=Deduplicator)
    enricher: Enricher = field(default_factory=lambda: default_enricher(offline=True))
    scorer: Scorer = field(default_factory=Scorer)
    responder: Responder = field(default_factory=Responder)

    enrich_from: int = 2     # don't spend quota on INFO-level noise;
                             # Severity value, 2 == MEDIUM and above

    def run(self, events: list[dict]) -> TriageResult:
        result = TriageResult(events_read=len(events))

        # 1. parse ------------------------------------------------------- #
        alerts: list[Alert] = [parse_event(event) for event in events]
        result.alerts_parsed = len(alerts)

        # 2. deduplicate ------------------------------------------------- #
        kept, suppressed = self.deduplicator.process(alerts)
        result.suppressed = suppressed

        # 3. enrich ------------------------------------------------------ #
        for alert in kept:
            if alert.severity.value < self.enrich_from:
                continue
            report = self.enricher.enrich(alert)
            result.reports[alert.fingerprint()] = report

        # 4. score ------------------------------------------------------- #
        for alert in kept:
            key = alert.fingerprint()
            result.scores.append(
                self.scorer.score(
                    alert,
                    result.reports.get(key),
                    self.deduplicator.count_for(alert),
                )
            )
        result.scores.sort(key=lambda s: -s.value)

        # 5. respond ----------------------------------------------------- #
        for score in result.scores:
            result.outcomes[score.alert.fingerprint()] = self.responder.respond(score)

        return result
