"""Pulling indicators out of free text.

A parser gets indicators from named fields — `src_ip`, `syscheck.sha256_after`.
But plenty of evidence only ever appears inside prose: a command line, a log
message, the body of a phishing email. This module digs those out.

The hard part is not finding things that look like indicators. It is rejecting
the things that only *look* like them. `kernel32.dll` matches every
domain-shaped regex ever written, and enriching it wastes an API call you do
not have to spare.
"""

import ipaddress
import re

from .observables import Observable, ObservableType

# --------------------------------------------------------------------------- #
# Patterns
# --------------------------------------------------------------------------- #

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>)\]]{4,2048}", re.IGNORECASE)
DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b"
)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}\b")
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")

# Threat reports and phishing analyses arrive "defanged" so nobody clicks them
# by accident. Undo that before matching.
DEFANG_SUBS = [
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}"), "."),
    (re.compile(r"\[:\]|\(:\)"), ":"),
    (re.compile(r"\[@\]|\(at\)|\[at\]", re.IGNORECASE), "@"),
    (re.compile(r"\bhxxp(s?)\b", re.IGNORECASE), r"http\1"),
]

# The single highest-value filter in this file. Without a real TLD list,
# "kernel32.dll", "setup.exe" and "document.write" all become domains.
VALID_TLDS = {
    "com", "net", "org", "edu", "gov", "mil", "int", "info", "biz", "io", "co",
    "uk", "us", "ca", "au", "de", "fr", "nl", "ru", "cn", "jp", "in", "br", "it",
    "es", "se", "no", "fi", "dk", "pl", "ch", "at", "be", "ie", "nz", "za", "mx",
    "kr", "sg", "hk", "tw", "il", "tr", "ua", "cz", "gr", "pt", "hu", "ro",
    "top", "xyz", "club", "online", "site", "shop", "app", "dev", "cloud", "tech",
    "space", "live", "life", "world", "today", "click", "link", "icu", "cyou",
    "zip", "mov", "gq", "tk", "ml", "cf", "ga", "su", "cc", "ws", "me", "tv",
    "pw", "buzz", "monster", "quest", "rest", "fun", "bar", "loan", "win",
}

# Things that pass every shape check and still mean nothing.
NOISE = {"localhost", "localdomain", "example.com", "example.org", "invalid"}


def refang(text: str) -> str:
    """Turn `hxxps://evil[.]com` back into `https://evil.com`."""
    for pattern, replacement in DEFANG_SUBS:
        text = pattern.sub(replacement, text)
    return text


def defang(value: str) -> str:
    """Make an indicator safe to paste into a ticket or a chat message."""
    return value.replace("http", "hxxp").replace(".", "[.]")


def is_real_domain(value: str) -> bool:
    """Would we be willing to look this up?"""
    value = value.strip(".").lower()
    if not value or "." not in value or len(value) > 253 or value in NOISE:
        return False
    labels = value.split(".")
    if any(not label or len(label) > 63 for label in labels):
        return False
    if any(label.startswith("-") or label.endswith("-") for label in labels):
        return False
    return labels[-1] in VALID_TLDS


def is_internal(value: str) -> bool:
    """RFC1918, loopback, link-local — our own space, never enriched."""
    try:
        return not ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def is_routable_ip(value: str) -> bool:
    """A real, public address that could plausibly be blocked."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.is_global and not address.is_multicast


def extract(text: str, include_internal: bool = True) -> list[Observable]:
    """Every indicator in a blob of text, deduplicated.

    URLs are matched before bare domains so a URL's host does not also appear
    as a standalone domain. Hashes are matched longest-first, because a SHA-256
    contains substrings that would otherwise look like an MD5.
    """
    text = refang(text or "")
    found: dict[str, Observable] = {}

    def add(kind: ObservableType, value: str) -> None:
        observable = Observable(kind, value)
        found.setdefault(observable.key(), observable)

    for match in URL_RE.finditer(text):
        add(ObservableType.URL, match.group(0).rstrip(".,;)"))

    for match in EMAIL_RE.finditer(text):
        add(ObservableType.EMAIL, match.group(0))

    for pattern, kind in ((SHA256_RE, ObservableType.SHA256),
                          (SHA1_RE, ObservableType.SHA1),
                          (MD5_RE, ObservableType.MD5)):
        for match in pattern.finditer(text):
            add(kind, match.group(0).lower())

    for match in IPV4_RE.finditer(text):
        value = match.group(0)
        if is_routable_ip(value):
            add(ObservableType.IPV4, value)
        elif include_internal and is_internal(value):
            add(ObservableType.IPV4, value)

    for match in DOMAIN_RE.finditer(text):
        value = match.group(0).lower()
        if is_real_domain(value):
            add(ObservableType.DOMAIN, value)

    return list(found.values())


def enrichable(observables: list[Observable]) -> list[Observable]:
    """The subset it is safe and useful to send to an external provider.

    Internal addresses leak your network topology to a vendor and burn quota
    for an answer you already know.
    """
    keep = []
    for observable in observables:
        if observable.type in (ObservableType.IPV4, ObservableType.IPV6):
            if is_internal(observable.value):
                continue
        if observable.type.is_hash or observable.type.is_network:
            keep.append(observable)
    return keep
