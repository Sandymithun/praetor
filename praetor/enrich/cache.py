"""Remembering answers, for the right length of time.

Intelligence ages at very different speeds. A file hash verdict is stable for
days — the file does not change. An IP reputation can flip within the hour when
a residential address is recycled to a new customer.

So a single global TTL is wrong in both directions: too long for addresses,
wastefully short for hashes.
"""

import time
from dataclasses import dataclass, field

from ..observables import ObservableType
from .result import EnrichmentResult, Verdict

# Seconds. Tuned to "how fast can this ground truth change?"
TTL_BY_TYPE: dict[ObservableType, int] = {
    ObservableType.SHA256: 7 * 86_400,
    ObservableType.SHA1: 7 * 86_400,
    ObservableType.MD5: 7 * 86_400,
    ObservableType.DOMAIN: 6 * 3_600,
    ObservableType.URL: 3_600,
    ObservableType.IPV4: 3_600,
    ObservableType.IPV6: 3_600,
    ObservableType.EMAIL: 24 * 3_600,
}
FALLBACK_TTL = 3_600

# An "I have never seen this" answer gets a much shorter life. A brand-new C2
# domain is unknown for exactly one day -- cache that for a week and you stay
# blind to it long after the rest of the world has caught up.
NEGATIVE_TTL = 900


def ttl_for(result: EnrichmentResult) -> int:
    if result.verdict in (Verdict.UNKNOWN, Verdict.ERROR):
        return NEGATIVE_TTL
    return TTL_BY_TYPE.get(result.observable.type, FALLBACK_TTL)


@dataclass
class Cache:
    """In-memory TTL cache keyed by (provider, observable).

    Real deployments put Redis behind this so several workers share one cache.
    The interface is deliberately small enough that swapping the backend is one
    class.
    """

    _store: dict[str, tuple[float, EnrichmentResult]] = field(default_factory=dict)
    hits: int = 0
    misses: int = 0

    @staticmethod
    def key(provider: str, observable) -> str:
        return f"{provider}|{observable.key()}"

    def get(self, provider: str, observable) -> EnrichmentResult | None:
        entry = self._store.get(self.key(provider, observable))
        if entry is None:
            self.misses += 1
            return None
        expires_at, result = entry
        if time.monotonic() >= expires_at:
            del self._store[self.key(provider, observable)]
            self.misses += 1
            return None
        self.hits += 1
        result.cached = True
        return result

    def put(self, result: EnrichmentResult) -> None:
        expires_at = time.monotonic() + ttl_for(result)
        self._store[self.key(result.provider, result.observable)] = (expires_at, result)

    def clear(self) -> None:
        self._store.clear()

    @property
    def hit_rate(self) -> float:
        total = self.hits + self.misses
        return self.hits / total if total else 0.0

    def __len__(self) -> int:
        return len(self._store)
