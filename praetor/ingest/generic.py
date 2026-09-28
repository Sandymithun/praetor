"""Fallback parser: anything no other parser claimed."""

import json
from datetime import datetime, timezone
from typing import Any, Iterator

from ..alert import Alert
from ..models import Severity

TITLE_KEYS = ("title", "message", "name", "signature", "description")
SEVERITY_KEYS = ("severity", "level", "priority", "risk")
HOST_KEYS = ("host", "hostname", "computer", "device")
USER_KEYS = ("user", "username", "account")
TIME_KEYS = ("timestamp", "@timestamp", "time", "event_time", "date")


def can_parse(event: Any) -> bool:
    return isinstance(event, dict)


def _flatten(obj: Any, prefix: str = "") -> Iterator[tuple[str, Any]]:
    if isinstance(obj, dict):
        for key, value in obj.items():
            yield from _flatten(value, f"{prefix}.{key}" if prefix else str(key))
    elif isinstance(obj, list):
        for index, value in enumerate(obj):
            yield from _flatten(value, f"{prefix}[{index}]")
    else:
        yield prefix, obj


def _first(flat: dict[str, Any], names: tuple[str, ...]) -> Any:
    for name in names:
        for path, value in flat.items():
            if path.rsplit(".", 1)[-1].lower() == name:
                return value
    return None


def parse(event: dict) -> Alert:
    flat = {k: v for k, v in _flatten(event) if isinstance(v, (str, int, float))}

    raw_severity = _first(flat, SEVERITY_KEYS)
    host = _first(flat, HOST_KEYS)
    user = _first(flat, USER_KEYS)

    try:
        timestamp = datetime.fromisoformat(str(_first(flat, TIME_KEYS)).replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        timestamp = datetime.now(timezone.utc)

    return Alert(
        source=str(event.get("vendor") or event.get("source") or "unknown"),
        title=str(_first(flat, TITLE_KEYS) or "Unclassified event")[:300],
        timestamp=timestamp,
        severity=Severity.from_any(raw_severity) if raw_severity is not None else Severity.MEDIUM,
        description=json.dumps(event)[:500],
        host=str(host) if host else None,
        user=str(user) if user else None,
        tags=["unmapped"],
        raw=event,
    )
