"""What an intelligence provider tells us about one indicator."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from ..observables import Observable


class Verdict(str, Enum):
    """A provider's opinion.

    UNKNOWN and ERROR are deliberately distinct from BENIGN, and that
    distinction is the most important idea in this package.

      BENIGN   - we asked, and the provider says it is fine
      UNKNOWN  - we asked, and the provider has never seen it
      ERROR    - we could not ask

    Novel malware is UNKNOWN to every feed by definition. Treat that as BENIGN
    and you have built a system that is blind to exactly the threats that
    matter most.
    """

    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"
    UNKNOWN = "unknown"
    ERROR = "error"


@dataclass
class EnrichmentResult:
    """One provider's answer about one observable."""

    provider: str
    observable: Observable
    verdict: Verdict = Verdict.UNKNOWN
    score: float = 0.0            # 0-100 badness, normalised across providers
    confidence: float = 0.5       # how much we trust this answer, 0.0-1.0
    summary: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    reference_url: str | None = None
    cached: bool = False
    error: str | None = None
    fetched_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def usable(self) -> bool:
        """Did we actually learn anything?"""
        return self.error is None and self.verdict is not Verdict.ERROR

    @property
    def convicting(self) -> bool:
        return self.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS)

    def __str__(self) -> str:
        return f"[{self.provider}] {self.observable} -> {self.verdict.value} ({self.score:.0f})"
