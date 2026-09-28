"""Choosing the right parser for an event."""

import logging
from typing import Any

from ..alert import Alert
from . import generic, suricata, wazuh

logger = logging.getLogger(__name__)

PARSERS = [suricata, wazuh]


def select_parser(event: Any):
    for parser in PARSERS:
        try:
            if parser.can_parse(event):
                return parser
        except Exception:
            logger.warning("%s.can_parse raised; skipping it", parser.__name__, exc_info=True)
    return generic


def parse_event(event: dict) -> Alert:
    parser = select_parser(event)
    try:
        return parser.parse(event)
    except Exception:
        logger.warning("%s.parse failed; falling back to generic", parser.__name__, exc_info=True)
        try:
            return generic.parse(event)
        except Exception:
            logger.error("generic parser failed too", exc_info=True)
            return Alert(
                source="unknown",
                title="Unparseable event",
                tags=["unmapped", "parse-failed"],
                raw=event if isinstance(event, dict) else {},
            )
