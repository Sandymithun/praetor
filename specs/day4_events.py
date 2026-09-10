"""DAY 4 — Reading events without falling over.

Copy this file to  tests/test_events.py  and make it pass.

WHERE IT GOES
    praetor/events.py

WHY IT MATTERS
    Security telemetry arrives as JSON Lines: one JSON object per line, millions
    of lines, written by software that occasionally crashes mid-write. Somewhere
    in that file there will be a truncated line.

    You have two options when you hit it:

        1. Raise      — one bad line destroys the whole batch, and you lose
                        every alert after it, including the one that mattered.
        2. Skip it    — count it, log it, carry on.

    Choose 2. In security tooling, resilience beats correctness at the edges:
    the cost of dropping one malformed line is one line, and the cost of
    stopping is everything after it.
"""

import json

import pytest

from praetor.events import ReadResult, read_jsonl


def write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


class TestHappyPath:
    def test_reads_one_object_per_line(self, tmp_path):
        path = write(tmp_path, "a.jsonl", '{"a": 1}\n{"a": 2}\n{"a": 3}\n')
        result = read_jsonl(path)
        assert [e["a"] for e in result.events] == [1, 2, 3]
        assert result.errors == 0

    def test_handles_a_missing_trailing_newline(self, tmp_path):
        path = write(tmp_path, "a.jsonl", '{"a": 1}\n{"a": 2}')
        assert len(read_jsonl(path).events) == 2

    def test_nested_objects_survive_intact(self, tmp_path):
        event = {"alert": {"signature": "x", "meta": {"tags": ["a", "b"]}}}
        path = write(tmp_path, "a.jsonl", json.dumps(event) + "\n")
        assert read_jsonl(path).events[0]["alert"]["meta"]["tags"] == ["a", "b"]


class TestResilience:
    def test_a_malformed_line_is_skipped_not_fatal(self, tmp_path):
        path = write(tmp_path, "a.jsonl", '{"a": 1}\nNOT JSON AT ALL\n{"a": 3}\n')
        result = read_jsonl(path)
        assert [e["a"] for e in result.events] == [1, 3]
        assert result.errors == 1

    def test_a_truncated_line_is_skipped(self, tmp_path):
        # What a crashed log writer actually leaves behind.
        path = write(tmp_path, "a.jsonl", '{"a": 1}\n{"a": 2, "b": \n{"a": 3}\n')
        assert read_jsonl(path).errors >= 1

    def test_blank_lines_are_ignored_and_are_not_errors(self, tmp_path):
        path = write(tmp_path, "a.jsonl", '{"a": 1}\n\n   \n{"a": 2}\n')
        result = read_jsonl(path)
        assert len(result.events) == 2
        assert result.errors == 0

    def test_errors_record_the_line_number(self, tmp_path):
        # "line 2 is broken" is actionable. "something is broken" is not.
        path = write(tmp_path, "a.jsonl", '{"a": 1}\nBROKEN\n')
        result = read_jsonl(path)
        assert result.error_lines == [2]

    def test_a_line_that_is_valid_json_but_not_an_object_is_an_error(self, tmp_path):
        # `42` and `"hello"` are legal JSON but they are not events.
        path = write(tmp_path, "a.jsonl", '{"a": 1}\n42\n"hello"\n[1,2]\n')
        result = read_jsonl(path)
        assert len(result.events) == 1
        assert result.errors == 3

    def test_an_empty_file_is_fine(self, tmp_path):
        path = write(tmp_path, "empty.jsonl", "")
        result = read_jsonl(path)
        assert result.events == []
        assert result.errors == 0

    def test_a_missing_file_raises(self, tmp_path):
        # This one SHOULD fail loudly: a typo'd path is an operator mistake,
        # not bad data, and silently returning nothing would hide it.
        with pytest.raises(FileNotFoundError):
            read_jsonl(tmp_path / "does-not-exist.jsonl")


class TestReadResult:
    """Return a small result object, not a bare list.

    A bare list cannot tell the caller "I also threw away 400 lines". Silent
    data loss is exactly the failure mode this module exists to avoid.
    """

    def test_reports_totals(self, tmp_path):
        path = write(tmp_path, "a.jsonl", '{"a": 1}\nBROKEN\n{"a": 2}\n')
        result = read_jsonl(path)
        assert result.total == 3        # lines we attempted
        assert len(result.events) == 2
        assert result.errors == 1

    def test_summary_is_human_readable(self, tmp_path):
        path = write(tmp_path, "a.jsonl", '{"a": 1}\nBROKEN\n')
        summary = read_jsonl(path).summary()
        assert "1" in summary and "error" in summary.lower()


class TestRealTelemetry:
    def test_reads_the_bundled_sample(self):
        # samples/suricata.jsonl ships with the project. Note that it contains
        # a DNS record as well as alerts -- a real eve.json is a mixture, and
        # filtering it is Day 5's job, not this module's. Reading is reading.
        result = read_jsonl("samples/suricata.jsonl")
        assert len(result.events) >= 4
        assert result.errors == 0
        assert all("timestamp" in e for e in result.events)
        assert sum(1 for e in result.events if e.get("event_type") == "alert") == 3
