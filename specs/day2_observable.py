"""DAY 2 — Observable: the things worth acting on.

Copy this file to  tests/test_observable.py  and make it pass.

WHAT YOU'RE BUILDING
    An "observable" (the industry word is also "indicator" or "IOC") is one
    concrete, checkable fact pulled out of an alert: an IP address, a domain, a
    file hash. It is the unit of everything that comes later — you look up an
    observable in threat intelligence, you block an observable at the firewall,
    and two alerts sharing an observable are probably the same incident.

WHERE IT GOES
    praetor/observables.py

WHY IT MATTERS
    An alert says "something bad happened". An observable says "here is the
    specific thing you can check or block". Without this type, everything
    downstream would be passing raw strings around and guessing what they mean.
"""

import pytest

from praetor.observables import Observable, ObservableType


class TestObservableType:
    """The kinds of thing we know how to reason about.

    Keep this list short for now. Every type you add is a type that every
    lookup, every rule and every action has to have an opinion about.
    """

    def test_the_types_we_need(self):
        assert ObservableType.IPV4.value == "ipv4"
        assert ObservableType.DOMAIN.value == "domain"
        assert ObservableType.URL.value == "url"
        assert ObservableType.SHA256.value == "sha256"
        assert ObservableType.MD5.value == "md5"
        assert ObservableType.USERNAME.value == "username"
        assert ObservableType.FILE_PATH.value == "file_path"

    def test_is_a_string_enum(self):
        # Inheriting from str means it serialises straight to JSON later and
        # compares cleanly against plain strings, which saves a lot of
        # .value everywhere.
        assert ObservableType.IPV4 == "ipv4"

    def test_hash_types_know_they_are_hashes(self):
        # Used constantly: "do I have a file hash I can look up?"
        assert ObservableType.SHA256.is_hash
        assert ObservableType.MD5.is_hash
        assert not ObservableType.IPV4.is_hash

    def test_network_types_know_they_are_network(self):
        # Used constantly: "is there something here I could block?"
        assert ObservableType.IPV4.is_network
        assert ObservableType.DOMAIN.is_network
        assert ObservableType.URL.is_network
        assert not ObservableType.SHA256.is_network
        assert not ObservableType.USERNAME.is_network


class TestObservable:
    def test_holds_a_type_and_a_value(self):
        ob = Observable(type=ObservableType.IPV4, value="185.220.101.5")
        assert ob.type is ObservableType.IPV4
        assert ob.value == "185.220.101.5"

    def test_whitespace_is_stripped(self):
        # Real alert fields arrive padded. If you don't strip here, you will
        # spend an hour one day wondering why "8.8.8.8" != "8.8.8.8 ".
        assert Observable(ObservableType.IPV4, "  8.8.8.8  ").value == "8.8.8.8"

    def test_optional_field_records_where_it_came_from(self):
        # When an analyst asks "why did you block that?", "it was in
        # destination.ip" is a much better answer than "it was in the alert".
        ob = Observable(ObservableType.IPV4, "1.2.3.4", field="destination.ip")
        assert ob.field == "destination.ip"

    def test_field_defaults_to_none(self):
        assert Observable(ObservableType.IPV4, "1.2.3.4").field is None


class TestObservableKey:
    """`key()` is the identity of an observable, used for deduplication.

    Two observables with the same key are the same thing, even if they arrived
    from different sensors in different letter cases.
    """

    def test_key_combines_type_and_value(self):
        ob = Observable(ObservableType.IPV4, "185.220.101.5")
        assert ob.key() == "ipv4:185.220.101.5"

    def test_key_is_lowercase(self):
        # One sensor sends EVIL.COM, another sends evil.com. Same domain.
        upper = Observable(ObservableType.DOMAIN, "EVIL.COM")
        lower = Observable(ObservableType.DOMAIN, "evil.com")
        assert upper.key() == lower.key()

    def test_same_value_different_type_is_a_different_key(self):
        # A username "admin" and a hostname "admin" are not the same thing.
        a = Observable(ObservableType.USERNAME, "admin")
        b = Observable(ObservableType.HOSTNAME, "admin")
        assert a.key() != b.key()

    def test_keys_deduplicate_in_a_set(self):
        # This is what you'll actually use it for.
        obs = [
            Observable(ObservableType.IPV4, "1.2.3.4"),
            Observable(ObservableType.IPV4, "1.2.3.4"),
            Observable(ObservableType.DOMAIN, "evil.com"),
        ]
        assert len({o.key() for o in obs}) == 2


class TestObservableIsFrozen:
    """An observable must not change after it is created.

    Think about why: observables get put in sets, used as dictionary keys, and
    shared between alerts that were correlated together. If one alert could
    edit an observable in place, it would silently change it for every other
    alert holding the same object — a bug that is close to impossible to find.

    Use @dataclass(frozen=True).
    """

    def test_cannot_be_modified(self):
        ob = Observable(ObservableType.IPV4, "1.2.3.4")
        with pytest.raises(Exception):
            ob.value = "5.6.7.8"

    def test_can_be_used_in_a_set(self):
        # frozen=True gives you __hash__ for free. Without it, this raises
        # "unhashable type".
        assert len({Observable(ObservableType.IPV4, "1.2.3.4")}) == 1


class TestReadability:
    def test_printing_one_is_useful(self):
        # You will print these constantly while debugging. Make it readable.
        # Implement __str__.
        ob = Observable(ObservableType.IPV4, "185.220.101.5")
        assert str(ob) == "ipv4=185.220.101.5"
