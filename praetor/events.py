"""Reading security telemetry from JSON Lines files."""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ReadResult:
    """What came out of a file — and what didn't."""

    events: list[dict[str, Any]] = field(default_factory=list)
    errors: int = 0
    error_lines: list[int] = field(default_factory=list)
    total: int = 0

    def summary(self) -> str:
        return (f"{len(self.events)} event(s) read from {self.total} line(s), "
                f"{self.errors} error(s)")
def read_jsonl(path) -> ReadResult:
    """Read one JSON object per line, skipping anything malformed."""
    path = Path(path)
    text = path.read_text(encoding="utf-8")

    result = ReadResult()
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue

        result.total += 1

        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            result.errors += 1
            result.error_lines.append(number)
            continue

        if not isinstance(parsed, dict):
            result.errors += 1
            result.error_lines.append(number)
            continue

        result.events.append(parsed)

    return result