"""Turning everything we know into one number -- and its receipts.

A security tool that prints `Risk: 87` and nothing else gets switched off
within a quarter. The first time it is wrong, nobody can find out why, so
nobody trusts it the next time it is right.

So the unit of output here is not a number. It is a number *plus the reasons
that produced it*, each reason phrased so an analyst can disagree with that
one line instead of distrusting the whole tool.

Everything this module reads was built in Weeks 1-3. It fetches nothing.
"""

import fnmatch
from dataclasses import dataclass, field
from enum import Enum

from .alert import Alert
from .enrich import EnrichmentReport
from .enrich.result import Verdict
from .models import Severity


class RiskBand(str, Enum):
    """The score, bucketed into something a human can act on."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return list(RiskBand).index(self)


# Score thresholds. Deliberately conservative at the top: CRITICAL means
# "wake someone up", and if that happens twice for nothing the pager gets
# muted and the system is worthless.
BANDS: list[tuple[int, RiskBand]] = [
    (85, RiskBand.CRITICAL),
    (65, RiskBand.HIGH),
    (40, RiskBand.MEDIUM),
    (15, RiskBand.LOW),
    (0, RiskBand.INFO),
]


class AssetTier(int, Enum):
    """How much we care about the machine involved.

    The same malware alert is a different incident on a test laptop and on the
    payroll database. No amount of threat intelligence can tell you that --
    only your own inventory can.
    """

    UNKNOWN = 0
    STANDARD = 1
    SENSITIVE = 2
    CRITICAL = 3


@dataclass
class AssetInventory:
    """Which hosts matter. Glob patterns, first match wins.

    In a real deployment this comes from a CMDB. Here it is a dict, because
    the point is the *concept* of asset context, not the plumbing.
    """

    patterns: dict[str, AssetTier] = field(default_factory=dict)

    def tier_for(self, host: str | None) -> AssetTier:
        if not host:
            return AssetTier.UNKNOWN
        for pattern, tier in self.patterns.items():
            if fnmatch.fnmatch(host.lower(), pattern.lower()):
                return tier
        return AssetTier.STANDARD


DEFAULT_INVENTORY = AssetInventory(
    patterns={
        "srv-db*": AssetTier.CRITICAL,
        "srv-dc*": AssetTier.CRITICAL,
        "srv-*": AssetTier.SENSITIVE,
        "wks-*": AssetTier.STANDARD,
    }
)


@dataclass
class Reason:
    """One line of the explanation.

    `weight` is this signal's own argument for badness, 0.0-1.0, independent
    of every other signal. `points` is filled in afterwards -- it is this
    reason's share of the final score, so the printed lines actually add up.
    """

    signal: str
    text: str
    weight: float
    points: int = 0

    def __str__(self) -> str:
        return f"{self.points:+4d}  {self.text}"


@dataclass
class RiskScore:
    """A verdict about one alert, with its working shown."""

    alert: Alert
    value: int = 0
    band: RiskBand = RiskBand.INFO
    confidence: float = 0.5
    reasons: list[Reason] = field(default_factory=list)
    partial: bool = False
    caveats: list[str] = field(default_factory=list)

    @property
    def auto_closable(self) -> bool:
        """May this be closed without a human ever seeing it?

        Three conditions, and `not partial` is the one that matters. Closing
        a case whose convicting lookup never came back is the worst thing
        this program can do -- worse than a false positive, because a false
        positive gets seen.
        """
        return (
            not self.partial
            and self.band in (RiskBand.INFO, RiskBand.LOW)
            and self.confidence >= 0.6
        )

    def explain(self) -> str:
        lines = [f"Risk {self.value} / 100  ({self.band.value}, confidence {self.confidence:.0%})"]
        for reason in sorted(self.reasons, key=lambda r: -r.points):
            lines.append(f"  {reason}")
        for caveat in self.caveats:
            lines.append(f"  !  {caveat}")
        return "\n".join(lines)

    def __str__(self) -> str:
        return f"{self.value}/100 {self.band.value}"


# --------------------------------------------------------------------------- #
# The signals
# --------------------------------------------------------------------------- #

# How much each sensor severity argues, on its own, that this matters.
SEVERITY_WEIGHT: dict[Severity, float] = {
    Severity.INFO: 0.02,
    Severity.LOW: 0.10,
    Severity.MEDIUM: 0.30,
    Severity.HIGH: 0.55,
    Severity.CRITICAL: 0.75,
}

# A confirmed malicious verdict is strong but never certain -- feeds are
# wrong, and a shared CDN address gets listed for someone else's crime.
VERDICT_WEIGHT: dict[Verdict, float] = {
    Verdict.MALICIOUS: 0.80,
    Verdict.SUSPICIOUS: 0.35,
    Verdict.BENIGN: 0.0,
    Verdict.UNKNOWN: 0.0,
    Verdict.ERROR: 0.0,
}

ASSET_WEIGHT: dict[AssetTier, float] = {
    AssetTier.UNKNOWN: 0.0,
    AssetTier.STANDARD: 0.05,
    AssetTier.SENSITIVE: 0.20,
    AssetTier.CRITICAL: 0.35,
}


def combine(weights: list[float]) -> float:
    """Noisy-OR: combine independent arguments without ever exceeding 1.0.

        combined = 1 - (1-w1)(1-w2)(1-w3)...

    Read it as "the chance that *no* signal is right". Two 0.5 signals give
    0.75, not 1.0. Ten 0.1 signals give 0.65, not 1.0.

    This is the whole reason the module does not just add points up. Plain
    addition lets five weak hints stack their way into an automatic firewall
    block, and that is how an automated system takes a company offline.
    """
    survival = 1.0
    for weight in weights:
        survival *= (1.0 - max(0.0, min(1.0, weight)))
    return 1.0 - survival


@dataclass
class Scorer:
    """Reads an alert and its enrichment; produces a RiskScore."""

    inventory: AssetInventory = field(default_factory=lambda: DEFAULT_INVENTORY)
    repeat_shoulder: int = 10          # repeats past this add nothing more

    def score(
        self,
        alert: Alert,
        report: EnrichmentReport | None = None,
        repeat_count: int = 1,
    ) -> RiskScore:
        reasons: list[Reason] = []
        caveats: list[str] = []

        # -- 1. what the sensor thought ---------------------------------- #
        severity_weight = SEVERITY_WEIGHT.get(alert.severity, 0.3)
        reasons.append(
            Reason(
                signal="severity",
                text=f"sensor severity is {alert.severity.label} ({alert.source})",
                weight=severity_weight,
            )
        )

        # -- 2. what the outside world knows ----------------------------- #
        if report is not None:
            for result in report.results:
                weight = VERDICT_WEIGHT.get(result.verdict, 0.0)
                if weight <= 0:
                    continue
                # A provider's own confidence scales its argument. Two engines
                # out of seventy is not the same evidence as forty-two.
                weight *= max(0.3, result.confidence)
                reasons.append(
                    Reason(
                        signal="intel",
                        text=f"{result.observable} {result.verdict.value} per {result.provider}"
                             + (f" - {result.summary}" if result.summary else ""),
                        weight=weight,
                    )
                )

        # -- 3. whose machine is it -------------------------------------- #
        tier = self.inventory.tier_for(alert.host)
        asset_weight = ASSET_WEIGHT[tier]
        if asset_weight > 0:
            reasons.append(
                Reason(
                    signal="asset",
                    text=f"host {alert.host} is a {tier.name.lower()} asset",
                    weight=asset_weight,
                )
            )

        # -- 4. is it happening a lot ------------------------------------ #
        if repeat_count > 1:
            # Logarithmic-ish: 2 repeats matter, the 400th does not add more.
            fraction = min(1.0, (repeat_count - 1) / self.repeat_shoulder)
            reasons.append(
                Reason(
                    signal="volume",
                    text=f"seen {repeat_count}x in the dedupe window",
                    weight=0.25 * fraction,
                )
            )

        # -- combine ------------------------------------------------------ #
        combined = combine([r.weight for r in reasons])
        value = int(round(combined * 100))
        self._attribute(reasons, value)

        partial = bool(report.partial) if report is not None else False
        confidence = self._confidence(alert, report, reasons)

        if report is not None:
            if report.errors:
                caveats.append(
                    f"{len(report.errors)} enrichment lookup(s) failed - "
                    "this score is based on incomplete evidence"
                )
            if report.skipped:
                caveats.append(
                    f"{len(report.skipped)} observable(s) were never looked up"
                )
        elif alert.observables:
            partial = True
            caveats.append("no enrichment was run for this alert")

        if "unmapped" in alert.tags:
            caveats.append("alert came from the fallback parser - fields may be wrong")

        band = self._band(value, partial)
        return RiskScore(
            alert=alert,
            value=value,
            band=band,
            confidence=confidence,
            reasons=reasons,
            partial=partial,
            caveats=caveats,
        )

    # ------------------------------------------------------------------ #

    @staticmethod
    def _attribute(reasons: list[Reason], total: int) -> None:
        """Split the final score across the reasons, largest remainder first.

        The maths that produced `total` is multiplicative, but a human reads a
        column of numbers and expects it to add up. So each reason is given
        its proportional share, and the rounding leftovers go to the biggest
        contributors. Cosmetic -- but it is the difference between an
        explanation people read and one they skip.
        """
        total_weight = sum(r.weight for r in reasons)
        if total_weight <= 0:
            return
        exact = [(total * r.weight / total_weight) for r in reasons]
        for reason, share in zip(reasons, exact):
            reason.points = int(share)
        leftover = total - sum(r.points for r in reasons)
        order = sorted(range(len(reasons)), key=lambda i: -(exact[i] - int(exact[i])))
        for i in order[:max(0, leftover)]:
            reasons[i].points += 1

    @staticmethod
    def _confidence(
        alert: Alert,
        report: EnrichmentReport | None,
        reasons: list[Reason],
    ) -> float:
        """How sure are we -- separate from how bad.

        `value` answers "how bad". This answers "how much evidence is this
        standing on". They are different questions and collapsing them is a
        classic mistake: a 90 built on one unverified sensor field is not the
        same object as a 90 with three independent confirmations.
        """
        confidence = 0.4
        if len(reasons) >= 2:
            confidence += 0.15
        if report is not None:
            usable = [r for r in report.results if r.usable]
            if usable:
                confidence += 0.15
                confidence += 0.20 * (sum(r.confidence for r in usable) / len(usable))
            if report.errors:
                confidence -= 0.25
            if report.skipped:
                confidence -= 0.10
        if "unmapped" in alert.tags:
            confidence -= 0.15
        return round(max(0.05, min(1.0, confidence)), 2)

    @staticmethod
    def _band(value: int, partial: bool) -> RiskBand:
        band = next(b for threshold, b in BANDS if value >= threshold)
        if partial and band.rank < RiskBand.MEDIUM.rank:
            # Incomplete evidence may not produce a "nothing to see here"
            # verdict. Floor it at MEDIUM so a human lays eyes on it.
            return RiskBand.MEDIUM
        return band


def score_all(
    alerts: list[Alert],
    reports: dict[str, EnrichmentReport] | None = None,
    repeats: dict[str, int] | None = None,
    scorer: Scorer | None = None,
) -> list[RiskScore]:
    """Score a batch, keyed by alert fingerprint."""
    scorer = scorer or Scorer()
    reports = reports or {}
    repeats = repeats or {}
    out = []
    for alert in alerts:
        key = alert.fingerprint()
        out.append(scorer.score(alert, reports.get(key), repeats.get(key, 1)))
    return sorted(out, key=lambda s: -s.value)
