"""DAY 5 — Your first parser: Suricata.

Copy this file to  tests/test_suricata.py  and make it pass.

WHERE IT GOES
    praetor/ingest/__init__.py      (empty file, makes it a package)
    praetor/ingest/suricata.py

WHAT SURICATA IS
    A network intrusion detection system. It watches traffic, matches it against
    thousands of community rules, and writes one JSON object per event to a file
    called eve.json. Look at samples/suricata.jsonl before you start.

WHAT YOU'RE WRITING
    can_parse(event) -> bool     cheap check: is this ours?
    parse(event)     -> Alert    the real work

TWO TRAPS ARE BURIED IN HERE
    Both are real, both have caused real outages, and both are in the tests
    below with an explanation. Read the test names before you write code.
"""

from datetime import timezone

import pytest

from praetor.alert import Alert
from praetor.events import read_jsonl
from praetor.ingest.suricata import can_parse, parse
from praetor.models import Severity
from praetor.observables import ObservableType


@pytest.fixture
def events():
    return read_jsonl("samples/suricata.jsonl").events


@pytest.fixture
def beacon(events):
    """The Cobalt Strike alert — an internal host talking to external C2."""
    return next(e for e in events if "Cobalt" in e["alert"]["signature"])


@pytest.fixture
def scan(events):
    """The SSH scan — an external host probing one of ours."""
    return next(e for e in events if "SSH Scan" in e["alert"]["signature"])


class TestCanParse:
    def test_accepts_a_suricata_alert(self, beacon):
        assert can_parse(beacon) is True

    def test_rejects_a_suricata_event_that_is_not_an_alert(self, events):
        # eve.json contains dns, http, flow and tls records too. We only want
        # alerts for now.
        dns = next(e for e in events if e.get("event_type") == "dns")
        assert can_parse(dns) is False

    def test_rejects_another_vendor(self):
        assert can_parse({"rule": {"level": 10}, "agent": {"name": "h"}}) is False

    @pytest.mark.parametrize("junk", [{}, {"event_type": "alert"}, {"alert": "not an object"}])
    def test_never_raises_on_junk(self, junk):
        # can_parse runs against every event from every source, including
        # hostile and malformed ones. It must return a bool, never explode.
        assert can_parse(junk) in (True, False)


class TestBasicFields:
    def test_source_and_title(self, beacon):
        alert = parse(beacon)
        assert isinstance(alert, Alert)
        assert alert.source == "suricata"
        assert alert.title == "ET MALWARE Cobalt Strike Beacon Observed"

    def test_keeps_the_original_event(self, beacon):
        assert parse(beacon).raw == beacon

    def test_description_mentions_the_category(self, beacon):
        assert "trojan" in parse(beacon).description.lower()

    def test_timestamp_is_parsed_and_timezone_aware(self, beacon):
        alert = parse(beacon)
        assert alert.timestamp.year == 2026
        assert alert.timestamp.hour == 9
        assert alert.timestamp.tzinfo is not None


class TestSeverityIsInverted:
    """TRAP 1 — Suricata counts severity BACKWARDS.

    In Suricata, `alert.severity` is a priority: **1 is the most urgent** and 3
    or 4 is routine. If you map it straight onto our scale, every genuine
    emergency arrives labelled "low" and gets ignored, and every piece of noise
    arrives labelled "critical".

    This is not a hypothetical. Getting a vendor's severity direction backwards
    is one of the most common bugs in detection pipelines, and it fails
    silently — nothing crashes, the numbers are just wrong forever.
    """

    def test_priority_one_is_critical(self, beacon):
        assert beacon["alert"]["severity"] == 1
        assert parse(beacon).severity is Severity.CRITICAL

    def test_priority_three_is_not_critical(self, scan):
        assert scan["alert"]["severity"] == 3
        assert parse(scan).severity is Severity.MEDIUM

    def test_the_full_mapping(self, beacon):
        def with_priority(p):
            event = {**beacon, "alert": {**beacon["alert"], "severity": p}}
            return parse(event).severity
        assert with_priority(1) is Severity.CRITICAL
        assert with_priority(2) is Severity.HIGH
        assert with_priority(3) is Severity.MEDIUM
        assert with_priority(4) is Severity.LOW


class TestHostIsTheVictimNotTheSensor:
    """TRAP 2 — the `host` field is the sensor, not the machine in trouble.

    Look at samples/suricata.jsonl: every alert has `"host": "sensor-core01"`.
    That is the *IDS appliance that saw the traffic*. It is not involved in the
    incident at all.

    Why this matters enormously: in a few weeks you'll write a response action
    that isolates a compromised host from the network. If `alert.host` is the
    sensor, that action takes your intrusion detection offline in the middle of
    an intrusion. You would be blinding yourself, automatically, at the worst
    possible moment.

    So: work out which end of the connection is *yours* and use that.
    Use the standard-library `ipaddress` module — `ip_address(x).is_private`
    tells you whether an address is inside RFC 1918 space (10.x, 192.168.x,
    172.16-31.x).

    Rule: prefer a private SOURCE (something of ours reaching out — a likely
    compromise) over a private DESTINATION (something of ours being probed).
    """

    def test_host_is_not_the_sensor(self, beacon):
        assert beacon["host"] == "sensor-core01"
        assert parse(beacon).host != "sensor-core01"

    def test_outbound_beacon_uses_the_internal_source(self, beacon):
        # 10.10.50.42 -> 185.220.101.5. Ours is the source.
        assert parse(beacon).host == "10.10.50.42"

    def test_inbound_scan_uses_the_internal_destination(self, scan):
        # 45.134.26.11 -> 10.10.30.20. Ours is the destination.
        assert parse(scan).host == "10.10.30.20"

    def test_sensor_name_is_kept_as_a_tag_not_thrown_away(self, beacon):
        # It's still useful — "which sensor saw this?" is a real question.
        # Just don't let it pretend to be the victim.
        assert "sensor:sensor-core01" in parse(beacon).tags

    def test_no_private_address_means_no_host(self, beacon):
        # External to external, seen in transit. We have no machine to name.
        event = {**beacon, "src_ip": "1.2.3.4", "dest_ip": "5.6.7.8"}
        assert parse(event).host is None


class TestObservables:
    def test_extracts_both_addresses(self, beacon):
        values = {o.value for o in parse(beacon).observables_of(ObservableType.IPV4)}
        assert values == {"10.10.50.42", "185.220.101.5"}

    def test_records_which_field_each_came_from(self, beacon):
        by_value = {o.value: o for o in parse(beacon).observables}
        assert by_value["10.10.50.42"].field == "src_ip"
        assert by_value["185.220.101.5"].field == "dest_ip"

    def test_extracts_the_tls_server_name(self, beacon):
        # SNI is the domain the client asked for — often the only readable
        # thing in an encrypted connection, and frequently the best indicator.
        domains = [o.value for o in parse(beacon).observables_of(ObservableType.DOMAIN)]
        assert "cdn-evil.top" in domains

    def test_extracts_the_http_hostname(self, events):
        http_alert = next(e for e in events if "User-Agent" in e.get("alert", {}).get("signature", ""))
        domains = [o.value for o in parse(http_alert).observables_of(ObservableType.DOMAIN)]
        assert "updates.badcdn.net" in domains

    def test_absent_optional_fields_do_not_crash(self, scan):
        # The scan alert has no tls and no http block at all.
        alert = parse(scan)
        assert alert.observables_of(ObservableType.DOMAIN) == []

    def test_no_duplicate_observables(self, beacon):
        # Same address in two fields must appear once.
        event = {**beacon, "dest_ip": "10.10.50.42"}
        keys = [o.key() for o in parse(event).observables]
        assert len(keys) == len(set(keys))


class TestEveryAlertInTheSampleParses:
    def test_no_crashes(self, events):
        parsed = [parse(e) for e in events if can_parse(e)]
        assert len(parsed) == 3          # 3 alerts + 1 dns record
        assert all(a.source == "suricata" for a in parsed)
        assert all(a.title for a in parsed)
