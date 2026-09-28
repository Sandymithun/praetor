"""DAY 7 — Make it a thing you can run.

Copy this file to  tests/test_cli.py  and make it pass.

WHERE IT GOES
    praetor/cli.py
    praetor/__main__.py       (three lines; lets you run `python -m praetor`)

WHY TODAY EXISTS
    Six days of library code with no way to run it is six days you cannot show
    anyone. Today you build the front door: point it at a file of telemetry, get
    readable normalised alerts out.

    This is also the first thing a reviewer will try, and for most of them it is
    the only thing they will try.
"""

import subprocess
import sys

from praetor.cli import format_alert, summarise
from praetor.events import read_jsonl
from praetor.ingest import parse_event


class TestFormatAlert:
    def test_one_line_per_alert_with_the_essentials(self):
        alert = parse_event(read_jsonl("samples/mixed.jsonl").events[3])
        line = format_alert(alert)
        assert "critical" in line.lower()
        assert "Cobalt" in line
        assert "suricata" in line

    def test_survives_an_alert_with_almost_nothing_in_it(self):
        assert isinstance(format_alert(parse_event({})), str)


class TestSummarise:
    def test_counts_by_severity(self):
        alerts = [parse_event(e) for e in read_jsonl("samples/mixed.jsonl").events]
        text = summarise(alerts)
        assert "4" in text
        assert "critical" in text.lower()

    def test_names_the_sensors_it_saw(self):
        alerts = [parse_event(e) for e in read_jsonl("samples/mixed.jsonl").events]
        text = summarise(alerts)
        assert "suricata" in text and "wazuh" in text

    def test_reports_unmapped_events_prominently(self):
        """If a sensor stops being recognised, this line is the alarm.

        Nobody reads logs. People do read the summary that prints every time
        they run the tool.
        """
        alerts = [parse_event(e) for e in read_jsonl("samples/mixed.jsonl").events]
        assert "unmapped" in summarise(alerts).lower()

    def test_empty_input_does_not_crash(self):
        assert isinstance(summarise([]), str)


class TestCommandLine:
    """Run it the way a person would."""

    def run(self, *args):
        return subprocess.run(
            [sys.executable, "-m", "praetor", *args],
            capture_output=True, text=True, timeout=60,
        )

    def test_processes_a_file(self):
        result = self.run("samples/mixed.jsonl")
        assert result.returncode == 0, result.stderr
        assert "Cobalt" in result.stdout
        assert "srv-web01" in result.stdout

    def test_prints_a_summary(self):
        result = self.run("samples/mixed.jsonl")
        assert "unmapped" in result.stdout.lower()

    def test_missing_file_fails_clearly(self):
        result = self.run("no-such-file.jsonl")
        assert result.returncode != 0
        # A stack trace is not an error message. Say what went wrong.
        assert "no-such-file" in (result.stderr + result.stdout)
        assert "Traceback" not in result.stderr

    def test_no_arguments_prints_usage(self):
        result = self.run()
        assert "usage" in (result.stdout + result.stderr).lower()
