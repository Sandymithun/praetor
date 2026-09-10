# Week 1 — from nothing to a working ingestion pipeline

By Sunday night you'll be able to run:

```
python -m praetor samples/mixed.jsonl
```

and get readable, normalised alerts out of four different sensors that all
describe the world differently. That's a real thing. It's the foundation every
other week sits on, and it's the part most people skip and regret.

---

## How each day works

Every day follows the same four steps. The rhythm matters more than the speed.

**1. Copy in today's specification**

```powershell
Copy-Item specs\day2_observable.py tests\test_observable.py
```

**2. Read it before you write anything.** All the way through. The comments
explain *why* each test exists, not just what it checks. They're the lesson.

**3. Make it pass.**

```powershell
python -m pytest tests\test_observable.py -v
```

Red, then green. When a test fails, read the failure message properly before
changing anything — pytest tells you the expected value and the actual one, and
learning to read that is half of debugging.

**4. Commit, log, push.**

```powershell
python -m pytest              # everything, not just today
git add -A
git commit                    # editor opens; write why, not what
git push
```

---

## Ground rules

**Write it yourself.** Don't paste from anywhere, including me. If you're stuck
for more than 30 minutes, ask me — I'll give you the concept or a smaller
version of the problem, not the answer.

**Don't open the zip.** It's my implementation of this same project. Reading it
would cost you the whole point of the exercise.

**Every day gets a commit**, including bad days. "Spent two hours confused about
why frozen dataclasses need `__hash__`" is a real entry and an honest one.

**Five minutes in `docs/LOG.md` before you close the laptop.** Built / broke /
decided / next. You'll thank yourself in an interview.

---

## Day 1 — Severity

**File:** `praetor/models.py` · **Spec:** `tests/test_models.py` *(already in place)*

Five severity levels and a `from_any()` that accepts every dialect vendors use.

**Python you'll meet**

- **`Enum`** — a fixed set of named values. `Severity.HIGH` instead of the
  string `"high"`, so a typo is an error rather than silent bad data.
- **`class Severity(int, Enum)`** — inheriting `int` as well makes the values
  comparable with `<` and `>`. You need this: `max(...)` on severities is
  something you'll do constantly, and alphabetically `"critical"` sorts before
  `"low"`, which is exactly backwards.
- **`@classmethod`** — a function belonging to the type, so you call it as
  `Severity.from_any("high")`. First argument is `cls`, not `self`.
- **`@property`** — makes `.label` work without parentheses.

**Security concept: normalisation at the edge.** Suricata says `1`. Wazuh says
`level 12`. A firewall says `"warning"`. Convert everything into one shape the
moment it arrives and nothing downstream ever has to care which sensor it came
from. Skip this and every later function fills up with `if source == "suricata"`.

**Think about before you code:** `TestSeverityFallback` encodes a real decision —
what to do with a value you don't recognise. Raise? Default to INFO? Default to
MEDIUM? Have an opinion before you read mine in the comment.

---

## Day 2 — Observable

**File:** `praetor/observables.py` · **Spec:** `specs/day2_observable.py`

The indicator type: an IP, a domain, a hash. The unit of everything later —
what you look up in threat intel, what you block, what tells you two alerts are
the same incident.

**Python you'll meet**

- **`@dataclass`** — generates `__init__`, `__repr__` and `__eq__` from field
  declarations. Enormously less boilerplate than writing them by hand.
- **`@dataclass(frozen=True)`** — makes it immutable and, importantly, hashable,
  so you can put it in a `set`. The tests explain why immutability matters here.
- **`__post_init__`** — runs after the generated `__init__`; where you'd
  normalise a value. On a frozen dataclass you can't just assign, so you'll need
  `object.__setattr__(self, "value", ...)`. That's a real wrinkle and worth
  understanding rather than working around.
- **`__str__`** — what `print(obj)` shows.

**Security concept: identity and deduplication.** `EVIL.COM` from one sensor and
`evil.com` from another are the same domain. `key()` is what makes them
collapse into one thing.

---

## Day 3 — Alert

**File:** `praetor/alert.py` · **Spec:** `specs/day3_alert.py`

The canonical shape every sensor gets converted into.

**Python you'll meet**

- **`field(default_factory=list)`** — the mutable default trap. Writing
  `observables: list = []` makes every alert you ever create share one list.
  There's a test for it, and it will fail if you get it wrong.
- **`hashlib.sha256`** — for the fingerprint.
- **`X | None`** type hints — the modern way to write "optional".

**Security concept: what makes two detections "the same".** The fingerprint
deliberately *excludes* the timestamp (so a rule firing 1,000 times in a minute
is one detection repeating) and deliberately *includes* the host (so the same
malware on two machines stays two incidents). Get that backwards and you either
drown in noise or hide a compromise spreading. Both tests are in the spec.

---

## Day 4 — Reading events

**File:** `praetor/events.py` · **Spec:** `specs/day4_events.py`

Read JSON Lines without one broken line destroying the batch.

**Python you'll meet**

- **`json.loads`** and catching **`json.JSONDecodeError`**.
- **`pathlib.Path`** — the modern way to handle file paths, and it works
  identically on Windows and Linux, which matters for you specifically.
- **`try/except`** with a deliberate decision about what to catch.
- **pytest's `tmp_path` fixture** — a real temporary directory per test, so
  file tests don't leave mess behind.

**Security concept: fail loud, not quiet.** A malformed line gets skipped and
*counted*. A missing file raises. The difference is that bad data is expected
and an operator typo isn't — and silently returning nothing would hide the
typo.

---

## Day 5 — Your first parser (Suricata)

**Files:** `praetor/ingest/__init__.py`, `praetor/ingest/suricata.py` ·
**Spec:** `specs/day5_suricata.py`

The longest day this week. Two real traps are buried in it, both explained in
the tests.

**Python you'll meet**

- **Packages** — a directory with `__init__.py` in it.
- **`dict.get()` with defaults**, and chaining it safely for nested data:
  `(event.get("tls") or {}).get("sni")`. Note `or {}` rather than `.get("tls", {})`
  — think about why, given a field could be present but `null`.
- **`datetime.fromisoformat`** and timezone-aware datetimes.
- **`ipaddress`** — `ip_address("10.1.2.3").is_private`. Standard library, and
  far better than a regex.

**Trap 1: Suricata counts severity backwards.** Priority 1 is the *most* urgent.
Map it straight through and every emergency arrives labelled "low".

**Trap 2: the `host` field is the sensor, not the victim.** In a few weeks
you'll write an action that isolates a compromised machine. If `alert.host` is
the IDS, that action takes your detection offline mid-intrusion.

---

## Day 6 — A second sensor, and choosing between them

**Files:** `praetor/ingest/wazuh.py`, `praetor/ingest/generic.py`,
`praetor/ingest/__init__.py` · **Spec:** `specs/day6_wazuh_registry.py`

One parser is a script. Two is an architecture.

**Python you'll meet**

- **Modules as values** — you can put modules in a list and pass them around.
  `select_parser()` returns a module.
- **`monkeypatch`** — a pytest fixture that temporarily replaces something, used
  in the last test to simulate a parser crashing.
- **Broad `except Exception`** — normally a smell, occasionally exactly right.
  The spec explains where the line is.

**Security concept: the fallback parser.** The most important thing you write
today. Without it, a vendor renaming a field makes a whole class of alerts
silently disappear — no error, no crash, just a hole in your detection that
you find out about months later during an incident.

---

## Day 7 — Make it runnable, then push it

**Files:** `praetor/cli.py`, `praetor/__main__.py`, `README.md` ·
**Spec:** `specs/day7_cli.py`

**Python you'll meet**

- **`sys.argv`** — command-line arguments. Use `argparse` if you want, but
  plain `sys.argv` is fine for two arguments and teaches more.
- **`__main__.py`** — what makes `python -m praetor` work. Three lines.
- **Exit codes** — `sys.exit(1)` on failure. Non-zero means "something went
  wrong", and it's how every other tool will know.
- **`subprocess.run`** in tests — running your own program the way a user would.

Then write the `README.md`: what it does, how to run it, what you learned. Keep
it short and honest. It's the first thing anyone reads.

**Finally, put it on GitHub.**

```powershell
git branch -M main                  # your git defaulted to "master"
winget install --id GitHub.cli      # then restart PowerShell
gh auth login
gh repo create praetor --public --source=. --remote=origin --push
```

---

## If you fall behind

Days 5 and 6 are each worth two of the others. If you're short on time, take
two days over Day 5 and let Day 6 slip into next week. **Do not skip Day 7** —
an unrunnable project is an invisible one, and a week that ends with something
you can show is worth more than a week that ends with more code.

## What you'll be able to say at the end of it

> "It ingests telemetry from multiple sensors and normalises it into one
> schema. Every sensor expresses severity differently — Suricata counts
> backwards, Wazuh uses 0-15 — so that gets converted at the edge. Unrecognised
> event shapes still produce a degraded alert rather than being dropped,
> because silent data loss is the failure mode that actually hurts you."

That's a better answer than most people give about projects they spent a month
on. And it'll be true.
