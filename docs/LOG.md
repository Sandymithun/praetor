# Engineering log

One entry per working day, newest first. Write it the same day — a log
reconstructed a week later is fiction, and fiction is no use in an interview.

**Four questions each time:**

- **Built** — what exists now that didn't this morning
- **Broke** — what went wrong, and what the cause turned out to be
- **Decided** — a choice you made, what you rejected, and why
- **Next** — the one thing you pick up tomorrow

The **Broke** and **Decided** lines are the valuable ones. "It worked first
time" is rarely true and never interesting. The two hours you lost to something
subtle is the interview answer — and it's gone unless you write it down today.

Bad days count. "Four hours failing to understand frozen dataclasses, here's
what finally clicked" is a real entry.

---

## Template

```markdown
## Day N — YYYY-MM-DD — <what the day was about>

**Built.**

**Broke.**

**Decided.**

**Next.**
```

---

## Day 0 — 2026-09-10 — Setup

**Built.** Project skeleton, git repository, and the Week 1 specifications.
Nothing runs yet — by design. The tests exist before the code does, so "done"
is defined by something other than my own opinion.

**Broke.** Nothing yet.

**Decided.** Writing this from scratch rather than starting from a working
implementation. Slower, and I'll cover less ground in the month — but a project
I can explain line by line is worth more than a bigger one I can't. Also chose
plain `dataclasses` over a library like pydantic for now: fewer moving parts
while I'm still learning the language.

**Next.** Day 1 — the `Severity` type. Read `tests/test_models.py` first.
