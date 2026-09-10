"""DAY 3 — Alert: one shape for every sensor.

Copy this file to  tests/test_alert.py  and make it pass.

WHERE IT GOES
    praetor/alert.py

WHY IT MATTERS
    This is the single most important decision in the whole project. Suricata,
    Wazuh and Sysmon all describe "something happened" completely differently.
    If you let those differences travel past the front door, every function you
    write for the rest of the month has to know which sensor it is dealing
    with, and adding a fifth sensor means touching every file.

    Convert once, at the edge, into one shape. Everything after that is simple.
"""

from datetime import datetime, timezone

import pytest

from praetor.alert import Alert
from praetor.models import Severity
from praetor.observables import Observable, ObservableType

T0 = datetime(2026, 9, 10, 9, 0, tzinfo=timezone.utc)


def ip(value: str) -> Observable:
    return Observable(ObservableType.IPV4, value)


class TestAlertFields:
    def test_minimum_viable_alert(self):
        # source and title are the only things we insist on. An alert we can't
        # attribute to a sensor, or can't describe to a human, is useless.
        alert = Alert(source="suricata", title="ET MALWARE Cobalt Strike Beacon")
        assert alert.source == "suricata"
        assert alert.title == "ET MALWARE Cobalt Strike Beacon"

    def test_sensible_defaults(self):
        alert = Alert(source="test", title="t")
        assert alert.severity is Severity.MEDIUM     # see Day 1: fail loud
        assert alert.host is None
        assert alert.user is None
        assert alert.observables == []
        assert alert.raw == {}

    def test_full_alert(self):
        alert = Alert(
            source="sysmon",
            title="Process creation: rundll32.exe",
            timestamp=T0,
            severity=Severity.HIGH,
            host="wks-042",
            user="CORP\\jdoe",
            observables=[ip("185.220.101.5")],
            raw={"EventID": 1},
        )
        assert alert.timestamp == T0
        assert alert.severity is Severity.HIGH
        assert alert.host == "wks-042"
        assert len(alert.observables) == 1

    def test_timestamp_defaults_to_now_in_utc(self):
        alert = Alert(source="test", title="t")
        assert alert.timestamp.tzinfo is not None, "always store timezone-aware times"
        assert (datetime.now(timezone.utc) - alert.timestamp).total_seconds() < 5

    def test_raw_keeps_the_original_event(self):
        """Never throw the original away.

        Six months from now someone will ask "but what did the sensor
        actually say?" — usually while investigating why your parser got
        something wrong. Keeping `raw` costs a little memory and saves entire
        afternoons.
        """
        original = {"event_type": "alert", "weird_vendor_field": 42}
        alert = Alert(source="suricata", title="t", raw=original)
        assert alert.raw["weird_vendor_field"] == 42


class TestMutableDefaultTrap:
    """A Python trap that will bite you eventually. Better it bites now.

    If you write `observables: list = []` in a dataclass, Python creates that
    list ONCE, when the class is defined — and every alert you ever create
    shares it. Append to one alert's observables and they all change.

    The fix is `field(default_factory=list)`, which runs `list()` fresh for
    each new object. Same for the `raw` dict.
    """

    def test_two_alerts_do_not_share_a_list(self):
        first = Alert(source="a", title="a")
        second = Alert(source="b", title="b")
        first.observables.append(ip("1.2.3.4"))
        assert second.observables == [], "your default is shared — use field(default_factory=list)"

    def test_two_alerts_do_not_share_a_dict(self):
        first = Alert(source="a", title="a")
        second = Alert(source="b", title="b")
        first.raw["poisoned"] = True
        assert second.raw == {}, "same trap, on the raw dict"


class TestFingerprint:
    """The identity of a detection, used to suppress repeats.

    A brute-force attack fires the same rule on the same host a thousand times
    in a minute. That is ONE thing happening, not a thousand things. The
    fingerprint is how you recognise the repeats.
    """

    def test_is_a_short_stable_string(self):
        alert = Alert(source="wazuh", title="brute force", host="srv-web01")
        first = alert.fingerprint()
        assert isinstance(first, str)
        assert 8 <= len(first) <= 64
        assert alert.fingerprint() == first, "must be stable across calls"

    def test_identical_detections_match(self):
        def make():
            return Alert(source="wazuh", title="brute force", host="srv-web01",
                         observables=[ip("45.134.26.11")])
        assert make().fingerprint() == make().fingerprint()

    def test_timestamp_is_deliberately_excluded(self):
        """The key insight of the whole test file.

        The same rule firing at 09:00 and at 09:01 is the same detection
        repeating. If you include the timestamp, every single event gets a
        unique fingerprint and deduplication does nothing at all.
        """
        early = Alert(source="wazuh", title="brute force", host="srv-web01",
                      timestamp=datetime(2026, 9, 10, 9, 0, tzinfo=timezone.utc))
        later = Alert(source="wazuh", title="brute force", host="srv-web01",
                      timestamp=datetime(2026, 9, 10, 9, 1, tzinfo=timezone.utc))
        assert early.fingerprint() == later.fingerprint()

    def test_different_host_is_a_different_detection(self):
        """And this is the other half.

        The same rule on two different machines is two incidents. Collapse
        those and you will hide a compromise spreading across the estate —
        which is exactly the thing you most need to see.
        """
        a = Alert(source="wazuh", title="brute force", host="srv-web01")
        b = Alert(source="wazuh", title="brute force", host="srv-db1")
        assert a.fingerprint() != b.fingerprint()

    def test_different_title_is_different(self):
        a = Alert(source="wazuh", title="brute force", host="h")
        b = Alert(source="wazuh", title="malware detected", host="h")
        assert a.fingerprint() != b.fingerprint()

    def test_different_observables_are_different(self):
        a = Alert(source="s", title="t", host="h", observables=[ip("1.1.1.1")])
        b = Alert(source="s", title="t", host="h", observables=[ip("2.2.2.2")])
        assert a.fingerprint() != b.fingerprint()

    def test_observable_order_does_not_matter(self):
        # Two sensors may list the same indicators in a different order.
        # Sort them before hashing.
        a = Alert(source="s", title="t", observables=[ip("1.1.1.1"), ip("2.2.2.2")])
        b = Alert(source="s", title="t", observables=[ip("2.2.2.2"), ip("1.1.1.1")])
        assert a.fingerprint() == b.fingerprint()

    def test_missing_host_does_not_crash(self):
        Alert(source="s", title="t", host=None).fingerprint()


class TestHelpers:
    def test_observables_of_filters_by_type(self):
        alert = Alert(source="s", title="t", observables=[
            ip("1.1.1.1"),
            Observable(ObservableType.SHA256, "a" * 64),
            Observable(ObservableType.DOMAIN, "evil.com"),
        ])
        assert len(alert.observables_of(ObservableType.IPV4)) == 1
        # Accepts several types at once — you'll want this for "anything
        # network-ish that I could block".
        assert len(alert.observables_of(ObservableType.IPV4, ObservableType.DOMAIN)) == 2
        assert alert.observables_of(ObservableType.MD5) == []
