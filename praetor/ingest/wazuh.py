"""Wazuh agent alerts -> Alert."""

from datetime import datetime, timezone
from typing import Any

from ..alert import Alert
from ..models import Severity
from ..observables import Observable, ObservableType


def can_parse(event: Any) -> bool:
    if not isinstance(event, dict):
        return False
    rule = event.get("rule")
    return isinstance(rule, dict) and "level" in rule and isinstance(event.get("agent"), dict)


def _severity_from_level(level: int) -> Severity:
    if level >= 12:
        return Severity.CRITICAL
    if level >= 9:
        return Severity.HIGH
    if level >= 6:
        return Severity.MEDIUM
    if level >= 3:
        return Severity.LOW
    return Severity.INFO


def _parse_timestamp(raw: Any) -> datetime:
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return datetime.now(timezone.utc)


def parse(event: dict) -> Alert:
    rule = event.get("rule") or {}
    agent = event.get("agent") or {}
    data = event.get("data") or {}
    syscheck = event.get("syscheck") or {}

    found: dict[str, Observable] = {}

    def add(kind: ObservableType, value: Any, where: str) -> None:
        if value:
            observable = Observable(kind, str(value), field=where)
            found.setdefault(observable.key(), observable)

    add(ObservableType.IPV4, data.get("srcip"), "data.srcip")
    add(ObservableType.IPV4, agent.get("ip"), "agent.ip")
    add(ObservableType.SHA256, syscheck.get("sha256_after"), "syscheck.sha256_after")
    add(ObservableType.FILE_PATH, syscheck.get("path"), "syscheck.path")

    user = data.get("dstuser") or data.get("srcuser")
    add(ObservableType.USERNAME, user, "data.dstuser")

    return Alert(
        source="wazuh",
        title=str(rule.get("description", "Wazuh alert")),
        timestamp=_parse_timestamp(event.get("timestamp")),
        severity=_severity_from_level(int(rule.get("level", 5) or 5)),
        description=str(event.get("full_log", ""))[:500],
        host=agent.get("name"),
        user=user,
        observables=list(found.values()),
        tags=["host"] + [str(g) for g in (rule.get("groups") or [])],
        raw=event,
    )
