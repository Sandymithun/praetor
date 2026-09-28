"""Enrichment: turning an alert's indicators into evidence.

An alert on its own says *something happened*. Enrichment answers *should I
care?* -- is that hash known malware, is that domain a week-old registration
on a bulletproof host, has anyone else on earth seen this before.

The orchestrator here does three jobs:

  * decides which observables are worth sending outside (extract.enrichable)
  * runs every provider that can speak to each one
  * collects the answers without ever letting one provider's failure look
    like a clean bill of health

That last point is the whole reason this file exists. A provider that times
out must produce an ERROR that the scorer can see, never an absence that the
scorer silently reads as "nothing found".
"""

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from ..alert import Alert
from ..extract import enrichable, extract
from ..observables import Observable
from .cache import Cache
from .limits import CircuitBreaker, QuotaExhausted, TokenBucket
from .result import EnrichmentResult, Verdict
from .virustotal import VirusTotal

__all__ = [
    "Cache",
    "CircuitBreaker",
    "EnrichmentReport",
    "EnrichmentResult",
    "Enricher",
    "MockProvider",
    "Provider",
    "QuotaExhausted",
    "TokenBucket",
    "Verdict",
    "VirusTotal",
]


@runtime_checkable
class Provider(Protocol):
    """What the orchestrator needs from any intelligence source.

    Four members. Anything satisfying these can be dropped in -- AbuseIPDB,
    an internal MISP instance, a CSV of known-bad hashes -- without the
    orchestrator changing at all.
    """

    name: str

    @property
    def configured(self) -> bool: ...

    def supports(self, observable: Observable) -> bool: ...

    def lookup(self, observable: Observable) -> EnrichmentResult: ...


@dataclass
class MockProvider:
    """An offline provider, for tests and for demos with no API key.

    Anything whose value contains a string from `bad` comes back MALICIOUS.
    Everything else is UNKNOWN -- not BENIGN, because a mock has no grounds
    to clear anything.
    """

    name: str = "mock"
    bad: set[str] = field(default_factory=lambda: {"evil.com", "185.220.101.5"})
    calls: int = field(default=0, init=False)

    @property
    def configured(self) -> bool:
        return True

    def supports(self, observable: Observable) -> bool:
        return observable.type.is_hash or observable.type.is_network

    def lookup(self, observable: Observable) -> EnrichmentResult:
        self.calls += 1
        value = observable.value.lower()
        if any(marker in value for marker in self.bad):
            return EnrichmentResult(
                provider=self.name,
                observable=observable,
                verdict=Verdict.MALICIOUS,
                score=90.0,
                confidence=0.9,
                summary="matched mock blocklist",
            )
        return EnrichmentResult(
            provider=self.name,
            observable=observable,
            verdict=Verdict.UNKNOWN,
            confidence=0.3,
            summary="not in mock blocklist",
        )


@dataclass
class EnrichmentReport:
    """Everything we learned about one alert."""

    alert: Alert
    results: list[EnrichmentResult] = field(default_factory=list)
    skipped: list[Observable] = field(default_factory=list)

    @property
    def convicting(self) -> list[EnrichmentResult]:
        return [r for r in self.results if r.convicting]

    @property
    def errors(self) -> list[EnrichmentResult]:
        return [r for r in self.results if not r.usable]

    @property
    def worst(self) -> EnrichmentResult | None:
        usable = [r for r in self.results if r.usable]
        return max(usable, key=lambda r: r.score) if usable else None

    @property
    def partial(self) -> bool:
        """True when at least one question went unanswered.

        Downstream scoring must show this to the analyst. A case enriched
        with half its providers down looks identical to a clean case unless
        somebody says so out loud.
        """
        return bool(self.errors) or bool(self.skipped)

    def for_observable(self, observable: Observable) -> list[EnrichmentResult]:
        return [r for r in self.results if r.observable.key() == observable.key()]

    def __str__(self) -> str:
        worst = self.worst
        head = f"{len(self.results)} lookup(s)"
        if worst is not None:
            head += f", worst={worst.verdict.value} ({worst.score:.0f})"
        if self.partial:
            head += f", PARTIAL ({len(self.errors)} error(s), {len(self.skipped)} skipped)"
        return head


@dataclass
class Enricher:
    """Runs a set of providers over an alert's observables."""

    providers: list[Provider] = field(default_factory=list)
    scan_text: bool = True          # also mine title/description for indicators
    max_observables: int = 25       # a hard stop, so one noisy alert cannot
                                    # drain the day's quota on its own

    def candidates(self, alert: Alert) -> list[Observable]:
        """Which indicators from this alert we are willing to look up."""
        found = list(alert.observables)
        if self.scan_text:
            text = f"{alert.title}\n{alert.description}"
            known = {o.key() for o in found}
            for observable in extract(text, include_internal=False):
                if observable.key() not in known:
                    known.add(observable.key())
                    found.append(observable)

        # Deduplicate by key, preserving order, then filter to what is safe
        # and useful to send outside.
        seen: set[str] = set()
        unique: list[Observable] = []
        for observable in found:
            if observable.key() in seen:
                continue
            seen.add(observable.key())
            unique.append(observable)
        return enrichable(unique)

    def enrich(self, alert: Alert) -> EnrichmentReport:
        wanted = self.candidates(alert)
        report = EnrichmentReport(alert=alert)

        if len(wanted) > self.max_observables:
            report.skipped.extend(wanted[self.max_observables:])
            wanted = wanted[: self.max_observables]

        for observable in wanted:
            answered = False
            for provider in self.providers:
                if not provider.supports(observable):
                    continue
                answered = True
                try:
                    report.results.append(provider.lookup(observable))
                except Exception as exc:          # a provider bug must not
                    report.results.append(        # kill the whole pipeline
                        EnrichmentResult(
                            provider=getattr(provider, "name", "unknown"),
                            observable=observable,
                            verdict=Verdict.ERROR,
                            confidence=0.0,
                            summary=f"provider raised {type(exc).__name__}",
                            error=str(exc),
                        )
                    )
            if not answered:
                report.skipped.append(observable)

        return report

    def enrich_all(self, alerts: list[Alert]) -> list[EnrichmentReport]:
        return [self.enrich(alert) for alert in alerts]


def default_enricher(offline: bool = False) -> Enricher:
    """The provider set we use unless told otherwise.

    With no VT_API_KEY, or with `offline=True`, you get the mock -- so the
    demo still runs end to end and nothing pretends to have consulted an
    intelligence feed it never reached.
    """
    if offline:
        return Enricher(providers=[MockProvider()])
    virustotal = VirusTotal()
    if virustotal.configured:
        return Enricher(providers=[virustotal])
    return Enricher(providers=[MockProvider()])
