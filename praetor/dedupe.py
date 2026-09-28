"""Suppressing repeats.

Alert fatigue is the problem this whole project exists to solve, and this is
the single crudest, most effective lever on it. A brute-force attack fires the
same rule thousands of times a minute. That is one thing happening, with a
count — not thousands of incidents.

Everything here leans on `Alert.fingerprint()` from Day 3, which deliberately
excludes the timestamp and deliberately includes the host.
"""

import time
from dataclasses import dataclass, field

from .alert import Alert


@dataclass
class Entry:
    """What we remember about one repeating detection."""

    alert: Alert
    count: int = 1
    first_seen: float = 0.0
    last_seen: float = 0.0


@dataclass
class Deduplicator:
    """Collapses identical detections seen inside a rolling time window.

    `window_seconds` is the memory. Too short and the same attack reappears
    every few minutes; too long and a genuinely new occurrence hours later gets
    silently folded into an old one. Fifteen minutes is a reasonable default
    for host and network alerts.
    """

    window_seconds: float = 900.0
    _seen: dict[str, Entry] = field(default_factory=dict)

    def submit(self, alert: Alert) -> tuple[Alert, bool]:
        """Returns (alert, is_new).

        Callers forward only new alerts into the expensive path — enrichment,
        scoring, notification. Repeats just bump a counter, so a 5,000-event
        burst costs one enrichment run instead of five thousand.
        """
        now = time.monotonic()
        self._evict(now)

        key = alert.fingerprint()
        entry = self._seen.get(key)

        if entry is None:
            self._seen[key] = Entry(alert=alert, first_seen=now, last_seen=now)
            return alert, True

        entry.count += 1
        entry.last_seen = now
        # Keep the worst severity ever seen for this detection.
        if alert.severity > entry.alert.severity:
            entry.alert.severity = alert.severity
        return entry.alert, False

    def count_for(self, alert: Alert) -> int:
        """How many times this detection has been seen in the window."""
        entry = self._seen.get(alert.fingerprint())
        return entry.count if entry else 0

    def process(self, alerts: list[Alert]) -> tuple[list[Alert], int]:
        """Filter a batch. Returns (new alerts, number suppressed)."""
        kept = []
        suppressed = 0
        for alert in alerts:
            canonical, is_new = self.submit(alert)
            if is_new:
                kept.append(canonical)
            else:
                suppressed += 1
        return kept, suppressed

    def _evict(self, now: float) -> None:
        expired = [k for k, e in self._seen.items() if now - e.last_seen > self.window_seconds]
        for key in expired:
            del self._seen[key]

    def __len__(self) -> int:
        return len(self._seen)
