"""VirusTotal v3, wired through quota, cache and circuit breaker.

Three deliberate choices worth understanding:

1. `urllib.request` from the standard library, not `requests`. One fewer
   dependency, and it forces you to see what an HTTP client actually does:
   build a request, set headers, handle the error status codes yourself.

2. Synchronous. Concurrency would be faster, but it would also hide the
   rate limiter behind a scheduler. You should be able to read this top to
   bottom and know exactly when a request leaves the machine.

3. The API key comes from the environment, never from a file in the repo.
   `VT_API_KEY=... python -m praetor ...`. No key means the provider
   reports itself unavailable -- loudly -- rather than silently answering
   "benign" to everything.
"""

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from ..observables import Observable, ObservableType
from .cache import Cache
from .limits import CircuitBreaker, QuotaExhausted, TokenBucket
from .result import EnrichmentResult, Verdict

API_ROOT = "https://www.virustotal.com/api/v3"

# Which VT endpoint answers for which observable type. Anything absent from
# this table, VirusTotal simply cannot speak to.
ENDPOINTS: dict[ObservableType, str] = {
    ObservableType.SHA256: "files",
    ObservableType.SHA1: "files",
    ObservableType.MD5: "files",
    ObservableType.DOMAIN: "domains",
    ObservableType.IPV4: "ip_addresses",
    ObservableType.IPV6: "ip_addresses",
    ObservableType.URL: "urls",
}

# Free tier, as published: 4 requests/minute, 500/day.
FREE_TIER_RATE = 4 / 60.0
FREE_TIER_BURST = 4.0
FREE_TIER_DAILY = 500


class ProviderUnavailable(RuntimeError):
    """We cannot ask this provider right now. Says nothing about the indicator."""


def _vt_url_id(url: str) -> str:
    """VirusTotal identifies a URL by its unpadded base64url encoding.

    Their docs call it "the URL identifier". It is just base64 with the
    trailing '=' stripped -- but get it wrong and every URL lookup 404s.
    """
    import base64

    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def _object_id(observable: Observable) -> str:
    if observable.type is ObservableType.URL:
        return _vt_url_id(observable.value)
    if observable.type.is_hash:
        return observable.value.lower()
    return observable.value


def _classify(stats: dict) -> tuple[Verdict, float, float]:
    """Turn VT's engine tally into (verdict, score 0-100, confidence 0-1).

    `stats` looks like {"malicious": 12, "suspicious": 1, "harmless": 60,
    "undetected": 5, "timeout": 0}.

    The thresholds matter. One engine out of seventy calling a file malicious
    is usually a heuristic false positive -- plenty of legitimate installers
    trip one scanner. Three or more independent engines agreeing is a
    different kind of evidence.
    """
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    harmless = int(stats.get("harmless", 0) or 0)
    undetected = int(stats.get("undetected", 0) or 0)
    total = malicious + suspicious + harmless + undetected

    if total == 0:
        # Nobody scanned it. That is UNKNOWN, and it is not the same as clean.
        return Verdict.UNKNOWN, 0.0, 0.2

    # Confidence grows with how many engines weighed in, and caps out.
    confidence = min(1.0, 0.3 + total / 70.0)

    if malicious >= 3:
        score = min(100.0, 60.0 + malicious * 3.0)
        return Verdict.MALICIOUS, score, confidence
    if malicious >= 1 or suspicious >= 2:
        score = 40.0 + malicious * 8.0 + suspicious * 4.0
        return Verdict.SUSPICIOUS, min(score, 59.0), confidence * 0.8
    if suspicious == 1:
        return Verdict.SUSPICIOUS, 35.0, confidence * 0.6
    return Verdict.BENIGN, 0.0, confidence


@dataclass
class VirusTotal:
    """A polite, self-limiting VirusTotal client.

    Every lookup passes four gates before a packet leaves the machine:
      cache -> circuit breaker -> daily quota -> rate limiter
    """

    api_key: str | None = None
    timeout: float = 15.0
    cache: Cache = field(default_factory=Cache)
    bucket: TokenBucket = field(
        default_factory=lambda: TokenBucket(
            rate=FREE_TIER_RATE, capacity=FREE_TIER_BURST, daily_limit=FREE_TIER_DAILY
        )
    )
    breaker: CircuitBreaker = field(default_factory=CircuitBreaker)
    wait_for_quota: float = 20.0

    name: str = "virustotal"

    def __post_init__(self) -> None:
        if self.api_key is None:
            self.api_key = os.environ.get("VT_API_KEY") or None

    # ----------------------------------------------------------------- #
    # Capability
    # ----------------------------------------------------------------- #

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    def supports(self, observable: Observable) -> bool:
        return observable.type in ENDPOINTS

    # ----------------------------------------------------------------- #
    # HTTP
    # ----------------------------------------------------------------- #

    def _get(self, path: str) -> dict:
        """One GET. Raises ProviderUnavailable, or returns parsed JSON.

        A 404 from VirusTotal means "never seen it" -- an answer, not a
        failure -- so it comes back as an empty dict rather than an error.
        """
        request = urllib.request.Request(
            f"{API_ROOT}/{path}",
            headers={"x-apikey": self.api_key or "", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return {}
            if exc.code in (401, 403):
                raise ProviderUnavailable(f"auth rejected (HTTP {exc.code})") from exc
            if exc.code == 429:
                raise ProviderUnavailable("rate limited by VirusTotal (HTTP 429)") from exc
            raise ProviderUnavailable(f"HTTP {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise ProviderUnavailable(f"network error: {exc.reason}") from exc
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ProviderUnavailable(f"malformed response: {exc}") from exc

    # ----------------------------------------------------------------- #
    # Lookup
    # ----------------------------------------------------------------- #

    def _error(self, observable: Observable, message: str) -> EnrichmentResult:
        return EnrichmentResult(
            provider=self.name,
            observable=observable,
            verdict=Verdict.ERROR,
            confidence=0.0,
            summary=message,
            error=message,
        )

    def lookup(self, observable: Observable) -> EnrichmentResult:
        """Ask about one observable. Never raises; always returns a result."""
        if not self.supports(observable):
            return self._error(observable, f"virustotal has no endpoint for {observable.type.value}")
        if not self.configured:
            return self._error(observable, "VT_API_KEY is not set")

        cached = self.cache.get(self.name, observable)
        if cached is not None:
            return cached

        if not self.breaker.allow():
            return self._error(observable, "circuit breaker open for virustotal")

        try:
            self.bucket.take(timeout=self.wait_for_quota)
        except QuotaExhausted as exc:
            return self._error(observable, f"quota exhausted: {exc}")
        except TimeoutError as exc:
            return self._error(observable, f"rate limited locally: {exc}")

        endpoint = ENDPOINTS[observable.type]
        try:
            payload = self._get(f"{endpoint}/{_object_id(observable)}")
        except ProviderUnavailable as exc:
            self.breaker.record_failure()
            return self._error(observable, str(exc))

        self.breaker.record_success()
        result = self._interpret(observable, payload)
        self.cache.put(result)
        return result

    def _interpret(self, observable: Observable, payload: dict) -> EnrichmentResult:
        attributes = (payload.get("data") or {}).get("attributes") or {}
        if not attributes:
            return EnrichmentResult(
                provider=self.name,
                observable=observable,
                verdict=Verdict.UNKNOWN,
                confidence=0.3,
                summary="not present in VirusTotal",
                reference_url=self.reference_url(observable),
            )

        stats = attributes.get("last_analysis_stats") or {}
        verdict, score, confidence = _classify(stats)

        engines = attributes.get("last_analysis_results") or {}
        naming = [
            info.get("result")
            for info in engines.values()
            if isinstance(info, dict) and info.get("category") == "malicious" and info.get("result")
        ]

        summary = (
            f"{stats.get('malicious', 0)}/{sum(int(v or 0) for v in stats.values())} engines malicious"
        )
        if naming:
            summary += f" ({naming[0]})"

        return EnrichmentResult(
            provider=self.name,
            observable=observable,
            verdict=verdict,
            score=score,
            confidence=confidence,
            summary=summary,
            reference_url=self.reference_url(observable),
            data={
                "stats": stats,
                "reputation": attributes.get("reputation"),
                "names": attributes.get("names", [])[:5],
                "detections": sorted(set(naming))[:5],
                "type_description": attributes.get("type_description"),
                "as_owner": attributes.get("as_owner"),
                "country": attributes.get("country"),
            },
        )

    def reference_url(self, observable: Observable) -> str:
        """A link an analyst can actually click during triage."""
        if observable.type.is_hash:
            return f"https://www.virustotal.com/gui/file/{observable.value}"
        if observable.type is ObservableType.URL:
            return f"https://www.virustotal.com/gui/url/{_vt_url_id(observable.value)}"
        if observable.type is ObservableType.DOMAIN:
            return f"https://www.virustotal.com/gui/domain/{observable.value}"
        return f"https://www.virustotal.com/gui/ip-address/{observable.value}"
