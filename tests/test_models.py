"""Tests for the canonical data model.

Read this file top to bottom before you write any code. It is the
specification: when every test here passes, the task is done.

Run it with:    python -m pytest -v
"""

import pytest

from praetor.models import Severity


class TestSeverityLevels:
    """Severity has five levels, and they must be comparable.

    Why comparable? Because the code that groups alerts together constantly
    needs to ask "which of these is worst?". If severity were a plain string,
    `max(alerts, key=...)` would sort alphabetically and decide that
    "critical" < "low", which is exactly backwards.
    """

    def test_has_five_levels(self):
        assert Severity.INFO.value == 0
        assert Severity.LOW.value == 1
        assert Severity.MEDIUM.value == 2
        assert Severity.HIGH.value == 3
        assert Severity.CRITICAL.value == 4

    def test_levels_are_ordered(self):
        assert Severity.CRITICAL > Severity.HIGH
        assert Severity.LOW < Severity.MEDIUM
        assert max([Severity.LOW, Severity.CRITICAL, Severity.MEDIUM]) is Severity.CRITICAL

    def test_label_is_the_lowercase_name(self):
        # Used when printing a case to a human, or tagging it "risk:critical".
        assert Severity.CRITICAL.label == "critical"
        assert Severity.INFO.label == "info"


class TestSeverityFromStrings:
    """Every vendor spells severity differently. We accept all of it.

    This is the whole reason `from_any` exists. Suricata says "1". Wazuh says
    "level 12". A firewall says "warning". A cloud provider says "SEVERE". None
    of them are wrong; they just aren't the same. Normalising at the edge means
    nothing downstream has to know or care which sensor an alert came from.
    """

    @pytest.mark.parametrize("text,expected", [
        ("critical", Severity.CRITICAL),
        ("high", Severity.HIGH),
        ("medium", Severity.MEDIUM),
        ("low", Severity.LOW),
        ("info", Severity.INFO),
    ])
    def test_plain_words(self, text, expected):
        assert Severity.from_any(text) is expected

    @pytest.mark.parametrize("text,expected", [
        ("CRITICAL", Severity.CRITICAL),
        ("High", Severity.HIGH),
        ("  medium  ", Severity.MEDIUM),      # vendors leave whitespace in fields
    ])
    def test_case_and_whitespace_do_not_matter(self, text, expected):
        assert Severity.from_any(text) is expected

    @pytest.mark.parametrize("synonym,expected", [
        ("severe", Severity.CRITICAL),
        ("emergency", Severity.CRITICAL),
        ("major", Severity.HIGH),
        ("error", Severity.HIGH),
        ("warning", Severity.MEDIUM),
        ("moderate", Severity.MEDIUM),
        ("minor", Severity.LOW),
        ("notice", Severity.INFO),
        ("informational", Severity.INFO),
    ])
    def test_real_world_synonyms(self, synonym, expected):
        assert Severity.from_any(synonym) is expected


class TestSeverityFromNumbers:
    def test_integers_map_to_levels(self):
        assert Severity.from_any(0) is Severity.INFO
        assert Severity.from_any(3) is Severity.HIGH

    def test_out_of_range_numbers_are_clamped(self):
        # A vendor sending 99 means "very bad", not "crash".
        assert Severity.from_any(99) is Severity.CRITICAL
        assert Severity.from_any(-5) is Severity.INFO

    def test_floats_are_accepted(self):
        # JSON has no integer type, so 3 often arrives as 3.0.
        assert Severity.from_any(3.0) is Severity.HIGH


class TestSeverityFallback:
    """What happens when we get something we don't understand?

    This is a real design decision, not a detail. There are three options:

      1. Raise an exception     -> one weird alert kills the whole batch
      2. Default to INFO        -> unknown alerts silently disappear
      3. Default to MEDIUM      -> unknown alerts get looked at

    We choose 3. In security tooling, failing quiet is the dangerous
    direction: an alert nobody sees is indistinguishable from an attack
    nobody detected.
    """

    @pytest.mark.parametrize("value", [
        "banana",          # a word we have never seen
        "",                # an empty field
        None,              # a missing field
        object(),          # something that isn't even text
    ])
    def test_unknown_values_become_medium(self, value):
        assert Severity.from_any(value) is Severity.MEDIUM

    def test_passing_a_severity_returns_it_unchanged(self):
        # from_any gets called on data that has sometimes already been
        # normalised. It must be safe to call twice.
        assert Severity.from_any(Severity.HIGH) is Severity.HIGH
