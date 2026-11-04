# Contributing to frisk

frisk is a security tool people point at hostile content, so the bar is: stdlib only, every
behaviour pinned by a test, and docs that a test keeps true. Security issues in frisk itself
go through [SECURITY.md](SECURITY.md), not a public issue.

## Setup

frisk has no runtime dependencies (`dependencies = []` in `pyproject.toml`) and supports
Python 3.9 and later, so a clone is all you need:

```bash
git clone https://github.com/Thandv/frisk && cd frisk
PYTHONPATH=src python3 -m frisk.cli examples/clean-skill
PYTHONPATH=src python3 -B -m unittest discover -s tests
```

Code must run on 3.9: `from __future__ import annotations` at the top of each module, no
3.10+ syntax (`match`, `X | Y` outside annotations) and no dataclass options newer than 3.9.
The optional extras are for tooling only: `test` (pytest) and `dev` (pytest, ruff, mypy,
coverage).

## Verify before you push

```bash
bash scripts/verify.sh
```

[`scripts/verify.sh`](scripts/verify.sh) is the local version of CI. For each interpreter
it finds (the macOS Command Line Tools `python3` and Homebrew's `python3.12` to
`python3.14`, deduplicated by real path, or exactly the paths in `FRISK_VERIFY_PYTHONS`) it
runs the stdlib unittest suite, and pytest too when pytest imports for that interpreter,
printing one PASS/FAIL line per run with the runner's name. It then runs `ruff check` and
`mypy src` when each is on PATH, and prints `skipped: <tool> not on PATH` otherwise. It
fails if any run fails, or if fewer than `FRISK_MIN_PYTHONS` (default 2) interpreters ran.
It installs nothing and uses no network.

What CI runs that verify.sh does not: Linux, the Python versions you do not have locally
(CI covers 3.9 to 3.14), the coverage report, and the `action-selftest` job, which runs the
composite Action on the examples (`.github/workflows/ci.yml`).

## Adding or changing a rule

1. **The rule.** Add a tuple to the right list in `src/frisk/rules.py` (`CODE_RULES`,
   `TEXT_RULES`, `INSTRUCTION_RULES` or `PROSE_RULES`): id, category, severity, pattern,
   the description frisk reports, and the `engine.scan_text` contexts it runs in. Every
   window in the pattern must be bounded, and stop at another start of the same rule, so
   the scan stays linear; `tests/test_perf.py` fails until the rule has seeds in its
   `SEEDS` table and scans 1 MiB of them within budget.
2. **Its documentation.** Add a `RuleDoc` to `scripts/rule_docs.py`: what it matches, why a
   hit matters, an example described in words, the likely false positive and what to do on
   a hit. `tests/test_rule_metadata.py` fails while a rule has no entry, and when the
   rationale or the example matches any rule's pattern.
3. **Tests in both directions.** A case the rule must catch and a near miss it must pass
   (the benign text people really write), built at test runtime (see the policy below).
   Show the test bites: break the pattern (drop a word from it, say), run the tests, see
   your test fail, and put the pattern back.
4. **Corpus cases.** When the labelled corpus exists (`corpus/<malicious|benign>/<case>/case.json`
   at the repository root, outside test collection), add a case for each direction, and flip
   only the `case.json` files your change makes pass from `known_gap` to `enforced`. There is
   no `corpus/` yet.
5. **Regenerate the docs.** `python3 scripts/gen_rules_doc.py` rewrites `docs/rules.md` from
   the rule tables and `scripts/rule_docs.py`; `python3 scripts/gen_readme_demo.py` rewrites
   the README's `<!-- frisk-demo: NAME -->` blocks from real runs (in a temp directory and
   HOME). Both take `--check`, which writes nothing and exits 1 when the file is stale;
   `tests/test_rules_doc.py` and `tests/test_docs.py` fail until you regenerate.
6. **A release note**, when the change alters what frisk reports (verdicts, findings,
   output shape, exit codes, flags): one fragment `changes/<ticket-id>.md`, as
   [changes/README.md](changes/README.md) says. Never edit `CHANGELOG.md` directly.

## Payloads in tests and fixtures

The repository is public, and frisk scans itself in its own tests, so:

- **Inert payloads only, built at runtime.** A test input that looks malicious or
  secret-shaped is assembled by string concatenation when the test runs, never committed
  as a literal (GitHub push protection and secret scanning must not fire, and the repo must
  not BLOCK its own scan). Hosts use the `.invalid` top-level domain. Nothing a test writes
  is ever executed.
- **No network, no real home directory.** Tests run frisk with a temp `HOME` and
  `XDG_STATE_HOME` (`tests/_subproc.py`, `tests/_home.py`) and never write into the
  repository.
- **No third-party content.** Do not paste a real attack, a published proof of concept or
  another project's files into a test, a fixture or the corpus: write an invented case that
  has the same shape.
- **Describe payloads in words** in code comments, docs and commit messages, the way
  `scripts/rule_docs.py` does. `tests/test_guides.py` fails when a user document (README,
  SECURITY, this file, `docs/`) has a block-level finding of its own.

## The docs are tested

- Every `frisk ...` line in a README bash fence ends with `[exit N]`, and
  `tests/test_readme_commands.py` runs it in a sandbox (temp working directory with a copy
  of `examples/`, temp HOME with a fixture MCP config); a fence that needs the network sits
  after a `<!-- doc-test: network -->` line and is not run.
- `tests/test_guides.py` checks every relative link and anchor in the README, SECURITY.md,
  this file and `docs/`, and that each flag and `FRISK_*` variable the proxy and frisk-mcp
  guides name exists in `src/frisk`.
- A user-facing change updates its doc line in the same commit.

## Foreman tickets

frisk work is often written up as Foreman tickets. In a ticket or brief:

- **Name the corpus case ids** a ticket flips, so its reviewer can check exactly those.
- **Describe payloads in words** ("a download piped into a shell", "an instruction to
  forget earlier instructions"), never as literal text: a brief may itself be scanned (by
  Foreman's admission scan, for one), where a literal payload is a finding.
- Keep one concern per ticket, and name the test file it adds.
