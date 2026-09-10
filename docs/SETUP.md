# Setting up from zero

You need four programs. This explains what each one is for before it tells you
to install it, because "install these five things" without knowing why is how
people end up stuck and unable to describe what's wrong.

Read Part 1 first. It's five minutes and it makes everything after it obvious.

---

## Part 1 — What the four tools actually do

### Python — the engine

A `.py` file is just a text file. It does nothing on its own. **Python** is a
program that reads that text and carries out the instructions.

When you type `python thing.py`, you're saying: *"Python, read thing.py and do
what it says."* Without Python installed, a `.py` file is as inert as a recipe
with no kitchen.

### VS Code — the desk

Where you write the text. You could genuinely use Notepad — the files are just
text. But **VS Code** is a text editor that understands code, so it:

- colours things so structure is visible at a glance
- underlines mistakes before you run anything
- has a terminal built in, so you're not alt-tabbing between windows

That last one matters more than it sounds.

### PowerShell — how you give orders

The black window where you type commands instead of clicking things.

This feels alien at first and then becomes faster than clicking. Every command
has the same shape: **the program you want, then what you want it to do.**

```
python -m pytest
└─┬──┘ └────┬───┘
  │         └── "run the module called pytest"
  └── the program
```

You'll use maybe ten commands for this entire project. They're at the bottom of
this file.

### Git — save points

Think of the save system in a game. **Git** takes a snapshot of your whole
folder whenever you tell it to (a *commit*), and you can go back to any snapshot
forever.

That's the real value: you can change anything without fear, because breaking
something is always undoable. Beginners often creep around their own code afraid
to touch it. Git removes that.

**GitHub** is a separate thing: a website that stores copies of your snapshots.
Git works fine with no internet; GitHub is where you put it so other people —
employers, for instance — can see it.

---

## Part 2 — Two Python-specific ideas

These trip up nearly everyone. Ten minutes now saves an afternoon later.

### Virtual environments — a toolbox per project

Python code uses **packages**: bundles of code other people wrote. Your project
needs one called `pytest`.

Install packages globally and every project on your machine shares one pile. Two
projects needing different versions of the same package will fight, and the loser
breaks in a way that is genuinely hard to diagnose.

A **virtual environment** is a private toolbox for one project. It's a real
folder — `.venv` — sitting inside your project, holding that project's packages
and nothing else.

```powershell
python -m venv .venv          # build the toolbox (once, per project)
.venv\Scripts\Activate.ps1    # step into it (every new terminal)
```

You know it worked when your prompt gains a green `(.venv)` prefix:

```
(.venv) PS C:\Users\mithu\Documents\praetor>
```

**If that prefix isn't there, you're not in the toolbox**, and `pip install` will
put things in the wrong place. This is the #1 source of "but I installed it!"
confusion. Check for the prefix.

### pytest — the exam marker

You write a claim about your code:

```python
def test_two_plus_two():
    assert 2 + 2 == 4
```

`assert` means *"this must be true; stop if it isn't."* **pytest** finds every
file named `test_*.py`, runs every function named `test_*`, and reports which
assertions held.

This project is built **test-first**: the test describing a piece of code exists
before the code does. That sounds backwards and isn't. It means "done" is
defined by something outside your own opinion — you're finished when the tests
go green, not when you feel finished. And it means you always know exactly what
you're trying to build next.

---

## Part 3 — Installing

Do these in order. Roughly 20 minutes, mostly waiting.

### 1. Python

1. Go to **<https://www.python.org/downloads/>**
2. Click the big yellow **Download Python 3.14.x** button
3. Run the installer

> ### The one thing you must not miss
>
> On the first installer screen there is a checkbox at the bottom:
>
> **☑ Add python.exe to PATH**
>
> **Tick it.** It is unticked by default.
>
> PATH is the list of folders Windows searches when you type a command. If
> Python isn't on it, typing `python` gets you `'python' is not recognized` even
> though Python is right there on your disk. This is the single most common
> Windows Python problem and it's caused by one unticked box.
>
> Then click **Install Now**.

### 2. VS Code

1. Go to **<https://code.visualstudio.com/>**
2. Download for Windows, run it
3. During install, tick **"Add to PATH"** and **"Open with Code"** for
   files and directories — those add a right-click "Open with Code" option that
   you'll use constantly

### 3. Git

1. Go to **<https://git-scm.com/download/win>**
2. Run the installer
3. **Accept every default.** The installer asks a lot of questions with
   sensible defaults, and none of the choices matter for you right now. Just
   keep clicking Next.

### 4. The Python extension for VS Code

1. Open VS Code
2. Click the **Extensions** icon in the left bar (four squares, one detached)
3. Search **Python**, install the one by **Microsoft**

That's it. Don't install anything else yet — extensions are easy to add later
and a wall of unfamiliar features now is just noise.

---

## Part 4 — Check it worked

Close any PowerShell windows you had open. Installers change PATH, and an
already-open window won't have noticed. Open a **fresh** PowerShell
(press Start, type `powershell`, Enter) and run these one at a time:

```powershell
python --version
git --version
code --version
```

You want three version numbers. `Python 3.14.7`, `git version 2.x`, `1.x`.

<details>
<summary><b>"python is not recognized"</b></summary>

Either PATH wasn't ticked, or Windows is intercepting the command.

**Try `py --version` first.** The `py` launcher is installed regardless of the
PATH setting. If that works, Python is fine — just use `py` everywhere this
guide says `python`.

**If Microsoft Store opens** when you type `python`, Windows has an "app
execution alias" hijacking the command. Turn it off:

Start → **Manage app execution aliases** → switch **off** both entries named
`python.exe` and `python3.exe`.

**Otherwise:** rerun the Python installer, choose **Modify**, and make sure
"Add Python to environment variables" is ticked.
</details>

<details>
<summary><b>"running scripts is disabled on this system"</b></summary>

You'll hit this the first time you try to activate a virtual environment.

Windows blocks PowerShell scripts by default. It's a reasonable security default
and it's safe to relax it for your own user account:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

Answer `Y`. This allows scripts you wrote yourself, while still requiring
scripts downloaded from the internet to be signed.
</details>

---

## Part 5 — Set up the project

```powershell
cd $HOME\Documents\praetor
```

**Clean up two things left over from earlier:**

```powershell
Remove-Item -Recurse -Force .git-stale -ErrorAction SilentlyContinue
git branch -M main
```

*(The second renames your branch from `master` to `main` — GitHub's default
since 2020. Purely cosmetic, but do it before you push.)*

**Tell git who you are.** It stamps this on every commit, and GitHub matches
commits to your account by the email:

```powershell
git config --global user.name "Kookie"
git config --global user.email "mithunsanthosh1@gmail.com"
```

**Build the toolbox and step into it:**

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

Look for the green `(.venv)` in your prompt before continuing.

**Install the project and its test tool:**

```powershell
pip install -e ".[dev]"
```

*`-e` means "editable": it links to your folder rather than copying it, so your
edits take effect immediately with no reinstalling. `[dev]` pulls in pytest.*

**Run the tests:**

```powershell
python -m pytest
```

You should see **failures** — specifically:

```
ModuleNotFoundError: No module named 'praetor.models'
```

**That is correct.** The test describing your first piece of code exists; the
code doesn't yet. That failure is your target for Day 1.

**Open the project:**

```powershell
code .
```

*(The `.` means "this folder".)*

---

## Part 6 — How a working session flows

```
   YOU                VS CODE            PYTHON              GIT
    │                    │                  │                 │
    │  write code   ───▶ │                  │                 │
    │                    │  saved as .py    │                 │
    │                    │  files in the    │                 │
    │                    │  praetor folder  │                 │
    │                    │        │         │                 │
    │  python -m pytest ─────────────────▶  │                 │
    │                    │                  │ reads your code │
    │                    │                  │ checks asserts  │
    │  ◀──────────── PASSED / FAILED ───────┘                 │
    │                    │                  │                 │
    │  git commit ────────────────────────────────────────▶   │
    │                    │                  │      snapshot   │
    │  git push ──────────────────────────────────────────▶ GitHub
```

The loop, all day: **write a bit → run the tests → fix → repeat.** When the
tests go green, commit. That's the whole job.

---

## Part 7 — The commands you'll actually use

Pin this section. It's genuinely all of them.

### Every time you open a new terminal

```powershell
cd $HOME\Documents\praetor
.venv\Scripts\Activate.ps1
```

### While working

| Command | What it does |
|---|---|
| `python -m pytest` | Run every test |
| `python -m pytest -v` | Same, listing each test by name |
| `python -m pytest tests\test_models.py` | Just one file — use this while working on one thing |
| `python -m pytest -x` | Stop at the first failure |
| `code .` | Open this folder in VS Code |

### Saving your work

| Command | What it does |
|---|---|
| `git status` | What's changed since the last snapshot |
| `git diff` | Show me the actual changes, line by line |
| `git add -A` | Mark everything to go in the next snapshot |
| `git commit` | Take the snapshot (opens an editor for the message) |
| `git log --oneline` | The history so far |
| `git push` | Send snapshots to GitHub (once it's set up on Day 7) |

### If something goes wrong

| Command | What it does |
|---|---|
| `git restore <file>` | Undo changes to one file since the last commit |
| `git restore --staged <file>` | Unstage a file, keep the change |
| `git log --oneline` | Find the snapshot you want to go back to |

---

## A note on getting stuck

You will get stuck. Everyone does, permanently, at every level — the difference
is only in what you get stuck on.

When it happens: **read the error message properly.** Beginners skim errors
because they look like noise. They aren't. Python errors read bottom-up — the
last line says what went wrong, and the lines above say where.

```
Traceback (most recent call last):
  File "praetor/models.py", line 12, in from_any
    return table[text]
KeyError: 'banana'
```

That says: in `models.py`, line 12, you looked up `'banana'` in a dictionary
that has no such key. That's a complete diagnosis. Most errors are.

If you're stuck more than 30 minutes, ask — with the **full error text** and
what you were trying. That's a much better question than "it doesn't work", and
you'll get a much better answer.
