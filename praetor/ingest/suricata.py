"""Suricata EVE JSON -> Alert."""

import ipaddress
from datetime import datetime
from typing import Any

from ..alert import Alert
from ..models import Severity
from ..observables import Observable, ObservableType

PRIORITY_TO_SEVERITY = {
    1: Severity.CRITICAL,
    2: Severity.HIGH,
    3: Severity.MEDIUM,
}


def can_parse(event: Any) -> bool:
    """Cheap check: is this event ours? Must never raise."""
    if not isinstance(event, dict):
        return False
    return event.get("event_type") == "alert" and isinstance(event.get("alert"), dict)

def _parse_timestamp(raw: Any) -> datetime:
    """Suricata's timestamp format into a real datetime."""
    text = str(raw).strip()
    if len(text) > 5 and text[-5] in "+-" and ":" not in text[-5:]:
        text = text[:-2] + ":" + text[-2:]
    return datetime.fromisoformat(text.replace("Z", "+00:00"))

def _is_internal(value: Any) -> bool:
    """Is this one of our own addresses?"""
    if not value:
        return False
    try:
        return ipaddress.ip_address(str(value)).is_private
    except ValueError:
        return False


def _victim_host(event: dict) -> str | None:
    """Which end of this connection is ours?

    Prefer an internal SOURCE (something of ours reaching out — a likely
    compromise) over an internal DESTINATION (something of ours being probed).
    """
    source = event.get("src_ip")
    destination = event.get("dest_ip")
    if _is_internal(source):
        return str(source)
    if _is_internal(destination):
        return str(destination)
    return None

def parse(event: dict) -> Alert:
    """Turn one Suricata EVE alert into a canonical Alert."""
    alert = event.get("alert") or {}

    priority = int(alert.get("severity", 3) or 3)
    severity = PRIORITY_TO_SEVERITY.get(priority, Severity.LOW)

    found: dict[str, Observable] = {}

    def add(kind: ObservableType, value: Any, where: str) -> None:
        if value:
            observable = Observable(kind, str(value), field=where)
            found.setdefault(observable.key(), observable)

    add(ObservableType.IPV4, event.get("src_ip"), "src_ip")
    add(ObservableType.IPV4, event.get("dest_ip"), "dest_ip")
    add(ObservableType.DOMAIN, (event.get("tls") or {}).get("sni"), "tls.sni")
    add(ObservableType.DOMAIN, (event.get("http") or {}).get("hostname"), "http.hostname")

    sensor = event.get("host")
    tags = ["network"] + ([f"sensor:{sensor}"] if sensor else [])

    return Alert(
        source="suricata",
        title=str(alert.get("signature", "Suricata alert")),
        timestamp=_parse_timestamp(event.get("timestamp")),
        severity=severity,
        description=f"{alert.get('category', 'network alert')} | "
                    f"{event.get('src_ip')} -> {event.get('dest_ip')}",
        host=_victim_host(event),
        observables=list(found.values()),
        tags=tags,
        raw=event,
    )