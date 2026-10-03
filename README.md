# Praetor

**An alert triage and response pipeline.** It reads security alerts from
several different sensors, works out which ones actually matter, explains its
reasoning line by line, and proposes containment — while refusing to do
anything destructive without a human saying yes.

---

## The problem

A small security team runs a network sensor and an agent on every machine.
Between them they produce tens of thousands of alerts a day. An analyst can
properly investigate a few dozen.

So most alerts are never read. Which means the one that mattered was almost
certainly generated — and almost certainly ignored.

Praetor sits between the sensors and the analyst and answers one question for
every alert: **should a human look at this?**

---

## Quickstart

```bash
git clone https://github.com/Sandymithun/praetor
cd praetor
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
python -m pytest -q                                # 130 tests

# normalise a mixed file of sensor telemetry
python -m praetor samples/mixed.jsonl

# the full pipeline: deduplicate, enrich, score, propose actions
python -m praetor --triage --offline --allow-disruptive samples/mixed.jsonl
```

No API key required — without one it uses an offline provider and says so,
rather than silently answering "benign" to everything.

To use real threat intelligence:

```bash
export VT_API_KEY=...            # Windows: $env:VT_API_KEY="..."
python -m praetor --triage samples/mixed.jsonl
```

---

## What it produces

Input — one line of machine-generated JSON:

```json
{"timestamp":"2026-09-10T09:12:04+0000","event_type":"alert",
 "src_ip":"10.10.50.42","dest_ip":"185.220.101.5",
 "alert":{"signature":"ET MALWARE Cobalt Strike Beacon Observed","severity":1}}
```

Output:

```
========================================================================
[critical] suricata   srv-db1          ET MALWARE Cobalt Strike Beacon Observed

Risk 99 / 100  (critical, confidence 88%)
   +27  sensor severity is critical (suricata)
   +26  ipv4=185.220.101.5 malicious per virustotal - 42/70 engines malicious
   +25  domain=cdn-evil.top malicious per virustotal - known C2 staging
   +12  host srv-db1 is a critical asset
    +9  seen 47x in the dedupe window

  TAG 01c85c8a8e25        [DRY RUN] - not performed
  NOTIFY #soc-alerts      [DRY RUN] - not performed
  BLOCK_IP 185.220.101.5  [DRY RUN] - not performed
  ISOLATE_HOST srv-db1    [DRY RUN] - not performed
```

A number, an explanation, and a proposed action. That is the whole project.

---

## How it works

```
events.jsonl
    │
    ▼  ingest/          many sensor formats → one Alert type
    ▼  dedupe.py        5,000 repeats → 1 case with a count
    ▼  extract.py       pull IPs, domains, hashes out of free text
    ▼  enrich/          ask threat intelligence, within quota
    ▼  scoring.py       0-100 risk + the reasons that produced it
    ▼  actions.py       propose containment, guard it, dry-run it
    │
    ▼  a case a human can act on
```

`pipeline.py` is the only file that knows this order. Reading it top to bottom
is the fastest way to understand the program.

---

## Five decisions worth defending

**1. Normalise at the edge.**
Every sensor describes the world differently. Suricata counts severity
*backwards* — priority 1 is the most urgent. Wazuh uses 0–15, higher is worse.
Both are converted into one `Severity` enum the moment they arrive, so nothing
downstream ever contains `if source == "suricata"`.

Suricata's `host` field is the *sensor*, not the victim — take it at face value
and your first automated response isolates your own IDS. `ingest/suricata.py`
resolves the internal endpoint of the flow instead.

**2. Deduplicate before enriching, not after.**
A brute-force attack fires the same rule thousands of times a minute. Enrich
first and a 5,000-event burst costs 5,000 API calls to learn one fact — the
entire daily intelligence budget, gone in ninety seconds. Cheap filters before
expensive work.

Duplicates are not discarded. They become a count, because "this fired 47
times" is itself evidence, and the count feeds the score.

**3. `UNKNOWN` is not `BENIGN`.**
Novel malware is unknown to every threat feed *by definition*. A system that
treats "no results" as "clean" is blind to exactly the threats that matter
most. `Verdict` keeps `BENIGN`, `UNKNOWN` and `ERROR` as three separate
things, and `EnrichmentReport.partial` propagates all the way into the
scoring and action layers.

**4. Evidence is combined, not added.**
Scoring uses noisy-OR — `1 - Π(1 - wᵢ)` — rather than summing points. Plain
addition lets five weak hints stack their way past an auto-block threshold,
which is how an automated system takes a company offline. Noisy-OR means one
strong signal dominates and weak ones saturate.

The printed points are each reason's *share* of the final score, so the column
adds up for the human reading it.

**5. Scoring decides what should happen; actions decide what may.**
Separate files, separate concerns. The guards in `actions.py` refuse to block
loopback, private ranges, link-local, multicast, reserved space, and a
never-block list of public DNS resolvers — every one of those corresponds to a
real way automated blocking has caused a real outage.

Dry-run is the permanent default. Arming it takes an explicit flag. A refused
action is never silently dropped; it produces an audit record saying what was
refused and why.

---

## The idea underneath all of it

> **In security tooling, silence is indistinguishable from safety.**

| Layer | What could fail quietly | What happens instead |
|---|---|---|
| `events.py` | a malformed line skipped | counted and reported |
| `dedupe.py` | 4,999 repeats discarded | kept as a count |
| `enrich/` | a timeout read as "clean" | `Verdict.ERROR` |
| `scoring.py` | partial evidence scored low | band floored, caveat printed |
| `actions.py` | a guard silently dropping an action | logged as `REFUSED` with a reason |

Every design decision in this project is that one sentence applied to a
different layer.

---

## Project layout

```
praetor/
  models.py        Severity — one scale every sensor converts into
  observables.py   Observable — one indicator: IP, domain, hash
  alert.py         Alert — the canonical shape, and its fingerprint
  events.py        resilient JSON-Lines reader
  ingest/          suricata.py, wazuh.py, generic.py, registry
  extract.py       indicators out of free text, noise rejected
  dedupe.py        sliding-window suppression
  enrich/
    result.py      Verdict, EnrichmentResult
    limits.py      TokenBucket, CircuitBreaker
    cache.py       per-type TTLs
    virustotal.py  VT v3 client, stdlib HTTP only
    __init__.py    Enricher, Provider protocol, MockProvider
  scoring.py       RiskScore, Scorer, AssetInventory
  actions.py       Action, guards, backends, Responder
  pipeline.py      the five stages, in order
  cli.py           the front door
tests/             130 tests
samples/           sensor telemetry to run against
```

No third-party runtime dependencies. HTTP is `urllib.request` from the
standard library — one fewer thing to audit, and nothing hidden behind a
convenience wrapper.

---

## Testing

```bash
python -m pytest -q
```

130 tests. They were written before the code they describe, which caught two
design errors early — a parser that would have isolated the IDS instead of the
victim, and an `Observable` type the schema never declared.

---

## What I would do next

- **Persistence.** Cases live in memory. A real deployment needs a case store
  so a restart does not lose the dedupe window and the audit log survives.
- **Correlation across alerts.** Right now each alert is scored alone. A failed
  login followed by a successful one followed by an outbound beacon is a story;
  three separate scores are not.
- **A real response backend.** The firewall and EDR are mocks by design. The
  `Backend` protocol is four methods — pointing it at a real appliance changes
  nothing else in the file.
- **Approval workflow.** Disruptive actions are currently all-or-nothing via a
  flag. They should queue for a named human with a timeout.
- **Shared cache.** The TTL cache is per-process. Redis behind the same
  interface would let several workers share one intelligence budget.

---

## Things I learned building this

- Where a rate limit belongs: enforced locally, before the request, not
  discovered from 429 responses after the budget is gone.
- Why `frozen=True` on a dataclass makes it hashable, and why an indicator you
  put in a set needs to be.
- That `isinstance(x, int)` is the wrong check for JSON input, because JSON has
  no integer type and `3` arrives as `3.0`.
- That the hard part of extracting indicators is not matching them. It is
  rejecting `kernel32.dll`, which satisfies every domain regex ever written.
- That the most dangerous code in a security tool is the code that acts, and
  the most valuable code is the code that refuses to.
