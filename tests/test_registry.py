"""DAY 6 — A second sensor, and choosing between them.

Copy this file to  tests/test_registry.py  and make it pass.

WHERE IT GOES
    praetor/ingest/wazuh.py
    praetor/ingest/generic.py
    praetor/ingest/__init__.py       (the registry lives here)

TODAY'S REAL LESSON
    One parser is a script. Two parsers is an architecture. The moment you have
    two, you need something that decides which to use — and the design of that
    decision is what determines whether adding a fifth sensor takes ten minutes
    or a week.

    You are also going to write a FALLBACK parser, and it is the most important
    thing you'll write today. See TestFallback for why.
"""

import pytest

from praetor.alert import Alert
from praetor.events import read_jsonl
from praetor.ingest import parse_event, select_parser
from praetor.ingest import wazuh
from praetor.models import Severity
from praetor.observables import ObservableType


@pytest.fixture
def wazuh_events():
    return read_jsonl("samples/wazuh.jsonl").events


@pytest.fixture
def brute(wazuh_events):
    return next(e for e in wazuh_events if e["rule"]["id"] == "5763")


# --------------------------------------------------------------------------- #
# Part 1 — the Wazuh parser
# --------------------------------------------------------------------------- #

class TestWazuhBasics:
    """Wazuh is a host agent: it watches logs, files and processes on a machine
    and reports back. Where Suricata sees the network, Wazuh sees the endpoint.
    """

    def test_can_parse_accepts_wazuh(self, brute):
        assert wazuh.can_parse(brute) is True

    def test_can_parse_rejects_suricata(self):
        assert wazuh.can_parse({"event_type": "alert", "alert": {"signature": "x"}}) is False

    def test_title_comes_from_the_rule_description(self, brute):
        alert = wazuh.parse(brute)
        assert alert.source == "wazuh"
        assert alert.title == "sshd: brute force trying to get access to the system"

    def test_host_is_the_agent(self, brute):
        # Unlike Suricata, here it really is the machine in trouble — the agent
        # runs ON the affected host. Different sensor, different meaning for
        # the same word. This is exactly why you normalise at the edge.
        assert wazuh.parse(brute).host == "srv-web01"

    def test_user_is_captured(self, brute):
        assert wazuh.parse(brute).user == "deploy"


class TestWazuhSeverity:
    """Wazuh rule levels run 0-15, and unlike Suricata they go the RIGHT way:
    higher is worse. Two sensors, two scales, opposite directions.

    Suggested mapping (you can argue for a different one — say why in your log):
        12+  critical      9-11  high      6-8  medium      3-5  low      0-2  info
    """

    def test_level_twelve_is_critical(self, wazuh_events):
        lateral = next(e for e in wazuh_events if e["rule"]["id"] == "92052")
        assert lateral["rule"]["level"] == 12
        assert wazuh.parse(lateral).severity is Severity.CRITICAL

    def test_level_ten_is_high(self, brute):
        assert wazuh.parse(brute).severity is Severity.HIGH

    def test_level_three_is_low(self, wazuh_events):
        success = next(e for e in wazuh_events if e["rule"]["id"] == "5715")
        assert wazuh.parse(success).severity is Severity.LOW


class TestWazuhObservables:
    def test_source_address_from_the_data_block(self, brute):
        ips = {o.value for o in wazuh.parse(brute).observables_of(ObservableType.IPV4)}
        assert "45.134.26.11" in ips

    def test_agent_address_is_included(self, brute):
        ips = {o.value for o in wazuh.parse(brute).observables_of(ObservableType.IPV4)}
        assert "10.10.30.20" in ips

    def test_file_integrity_events_yield_a_hash_and_a_path(self, wazuh_events):
        fim = next(e for e in wazuh_events if e["rule"]["id"] == "550")
        alert = wazuh.parse(fim)
        hashes = alert.observables_of(ObservableType.SHA256)
        paths = alert.observables_of(ObservableType.FILE_PATH)
        assert len(hashes) == 1 and hashes[0].value.startswith("112233")
        assert len(paths) == 1 and paths[0].value == "/var/backups/db/dump.sql"

    def test_missing_optional_blocks_do_not_crash(self, brute):
        # brute has no syscheck block at all.
        assert wazuh.parse(brute).observables_of(ObservableType.SHA256) == []


# --------------------------------------------------------------------------- #
# Part 2 — the registry
# --------------------------------------------------------------------------- #

class TestSelectParser:
    """`select_parser(event)` returns the module that should handle it."""

    def test_picks_suricata(self):
        from praetor.ingest import suricata
        event = {"event_type": "alert", "alert": {"signature": "x", "severity": 2},
                 "timestamp": "2026-09-10T09:00:00.000000+0000"}
        assert select_parser(event) is suricata

    def test_picks_wazuh(self, brute):
        assert select_parser(brute) is wazuh

    def test_falls_back_for_an_unknown_vendor(self):
        from praetor.ingest import generic
        assert select_parser({"vendor": "acme", "message": "something"}) is generic


class TestFallback:
    """The most important thing you write today.

    It is tempting to make an unrecognised event an error, or to drop it. Do
    neither. A vendor changes a field name in an update, your parser stops
    matching, and from that moment those alerts silently vanish. Nobody gets an
    error. Nobody notices. A whole class of detection is simply gone, and you
    find out months later — during an incident, if at all.

    A fallback parser turns a *silent* failure into a *visible degraded* one:
    the alert still arrives, tagged as unmapped, with whatever could be
    salvaged. Someone reviewing the unmapped queue sees the problem in a day.
    """

    def test_an_unknown_event_still_becomes_an_alert(self):
        alert = parse_event({"vendor": "acme-dlp", "severity": "low",
                             "message": "User downloaded 3 files",
                             "user": "jdoe", "hostname": "wks-042"})
        assert isinstance(alert, Alert)
        assert alert.title == "User downloaded 3 files"

    def test_it_is_tagged_so_it_can_be_found_later(self):
        assert "unmapped" in parse_event({"vendor": "acme", "message": "x"}).tags

    def test_it_salvages_what_it_can(self):
        alert = parse_event({"vendor": "acme-dlp", "severity": "low",
                             "message": "x", "user": "jdoe", "hostname": "wks-042"})
        assert alert.severity is Severity.LOW
        assert alert.host == "wks-042"
        assert alert.user == "jdoe"

    def test_total_junk_still_produces_something(self):
        alert = parse_event({"a": [1, {"b": None}], "c": 3})
        assert isinstance(alert, Alert)
        assert alert.title                       # some placeholder, not empty
        assert alert.raw == {"a": [1, {"b": None}], "c": 3}

    def test_an_empty_event_does_not_crash(self):
        assert isinstance(parse_event({}), Alert)


class TestParseEvent:
    def test_routes_a_mixed_file_correctly(self):
        events = read_jsonl("samples/mixed.jsonl").events
        alerts = [parse_event(e) for e in events]
        assert [a.source for a in alerts] == ["suricata", "wazuh", "acme-dlp", "suricata"]

    def test_every_alert_from_every_sensor_has_the_same_shape(self):
        """The payoff for the whole week.

        Below this line, nothing in the project ever needs to know which sensor
        an alert came from. That is the entire point of days 1 to 6.
        """
        events = read_jsonl("samples/mixed.jsonl").events
        for alert in (parse_event(e) for e in events):
            assert isinstance(alert.severity, Severity)
            assert alert.timestamp.tzinfo is not None
            assert isinstance(alert.observables, list)
            assert isinstance(alert.fingerprint(), str)

    def test_a_broken_parser_cannot_take_down_the_batch(self, monkeypatch):
        """Defence in depth.

        Your Suricata parser will have a bug one day. When it does, it must
        cost you Suricata alerts — not every alert from every sensor.
        """
        from praetor.ingest import suricata

        def exploding(event):
            raise RuntimeError("kaboom")

        monkeypatch.setattr(suricata, "parse", exploding)
        events = read_jsonl("samples/mixed.jsonl").events
        alerts = [parse_event(e) for e in events]
        assert len(alerts) == 4                          # nothing was lost
        assert any(a.source == "wazuh" for a in alerts)  # other sensors fine
