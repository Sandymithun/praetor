"""Living inside someone else's rate limit.

VirusTotal's free tier allows 4 requests per minute and 500 per day. Fire
lookups naively during an alert storm and you burn the entire daily allowance
in ninety seconds, then run blind until midnight.

Everything here exists to make quota a first-class, testable concept rather
than something you discover by collecting 429 responses.
"""

import time
from dataclasses import dataclass, field


class QuotaExhausted(RuntimeError):
    """The daily allowance is gone. Not retryable today."""


@dataclass
class TokenBucket:
    """Classic token bucket, plus a hard daily ceiling.

    `capacity` tokens refill at `rate` per second. Taking a token costs one
    request. When the bucket is empty you wait, or give up.

    The daily limit is enforced locally rather than discovered remotely,
    because discovering it means having already wasted the requests.
    """

    rate: float                       # tokens per second
    capacity: float = 4.0
    daily_limit: int | None = None

    _tokens: float = field(default=0.0, init=False)
    _updated: float = field(default_factory=time.monotonic, init=False)
    _spent_today: int = field(default=0, init=False)
    _day: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        self._tokens = self.capacity
        self._day = int(time.time() // 86_400)

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._updated
        if elapsed > 0:
            self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
            self._updated = now

    def _roll_day(self) -> None:
        today = int(time.time() // 86_400)
        if today != self._day:
            self._day = today
            self._spent_today = 0

    def try_take(self) -> bool:
        """Take a token if one is free. Never blocks.

        This is what batch enrichment wants: one exhausted provider should not
        stall the whole run.
        """
        self._roll_day()
        if self.daily_limit is not None and self._spent_today >= self.daily_limit:
            return False
        self._refill()
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            self._spent_today += 1
            return True
        return False

    def take(self, timeout: float = 30.0) -> None:
        """Wait for a token. Raises on timeout or exhausted quota."""
        deadline = time.monotonic() + timeout
        while True:
            self._roll_day()
            if self.daily_limit is not None and self._spent_today >= self.daily_limit:
                raise QuotaExhausted(f"daily limit of {self.daily_limit} reached")
            if self.try_take():
                return
            if time.monotonic() >= deadline:
                raise TimeoutError(f"no token within {timeout}s")
            time.sleep(min(0.25, 1.0 / self.rate))

    @property
    def spent_today(self) -> int:
        self._roll_day()
        return self._spent_today

    @property
    def remaining_today(self) -> int | None:
        if self.daily_limit is None:
            return None
        return max(0, self.daily_limit - self.spent_today)


@dataclass
class CircuitBreaker:
    """Stop hammering a provider that is down.

    Without this, a provider returning 500s turns every case into a pile of
    timeouts and throughput collapses to that provider's latency.
    """

    failure_threshold: int = 5
    recovery_seconds: float = 60.0

    _failures: int = field(default=0, init=False)
    _opened_at: float = field(default=0.0, init=False)
    _open: bool = field(default=False, init=False)

    def allow(self) -> bool:
        if not self._open:
            return True
        if time.monotonic() - self._opened_at >= self.recovery_seconds:
            self._open = False          # half-open: let one probe through
            self._failures = 0
            return True
        return False

    def record_success(self) -> None:
        self._failures = 0
        self._open = False

    def record_failure(self) -> None:
        self._failures += 1
        if self._failures >= self.failure_threshold:
            self._open = True
            self._opened_at = time.monotonic()

    @property
    def is_open(self) -> bool:
        return self._open
