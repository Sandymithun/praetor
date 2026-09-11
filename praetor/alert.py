"""The canonical alert: one shape that every sensor gets converted into."""

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .models import Severity
from .observables import Observable, ObservableType


def utcnow() -> datetime:
    """Current time, always timezone-aware and always in UTC."""
    return datetime.now(timezone.utc)


@dataclass
class Alert:
    """One detection, normalised. Every parser produces one of these."""

    source: str
    title: str

    timestamp: datetime = field(default_factory=utcnow)
    severity: Severity = Severity.MEDIUM
    description: str = ""
    host: str | None = None
    user: str | None = None

    observables: list[Observable] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    def fingerprint(self) -> str:
        """A stable id for 'this same detection', used to suppress repeats."""
        parts = [
            self.source,
            self.title,
            self.host or "",
            *sorted(o.key() for o in self.observables),
        ]
        return hashlib.sha256("|".join(parts).encode()).hexdigest()[:32]

    def observables_of(self, *types: ObservableType) -> list[Observable]:
        """Every observable matching any of the given types."""
        wanted = set(types)
        return [o for o in self.observables if o.type in wanted]