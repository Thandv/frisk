# Status

Where frisk stands today: what it is, what is shown to work and how, what is not tested, and
what only the owner can do. `tests/test_doc_truth.py` keeps the facts below true (the version,
the next release, the commands, every file, flag and module named here). Dated lines are a
record, not checked.

## Facts

- Version in the source: `0.2.0` (`__version__` in `src/frisk/__init__.py`).
- On PyPI (as `frisk-scan`): 0.1.0 only. 0.2.0 was tagged but never uploaded: its proxy fails
  open. The floating `v0` Action tag still points at the 0.2.0 commit.
- Next release: `0.3.0` (CHANGELOG.md's Unreleased section, steps in [RELEASING.md](RELEASING.md)).
- Commands: `frisk` (a scan, `frisk lock`, `frisk verify`, `frisk proxy`) and `frisk-mcp`.
  There is no `frisk-scan` command (see [Owner-held items](#owner-held-items)).
- Runtime dependencies: none (stdlib only); Python 3.9 and later.

## What works, and the evidence

Each line names the tests that pin the behaviour. They run offline with a temp HOME.

- **Scanning** a directory, a file, `--text` or `--stdin`, with the text report, `--json`,
  `--sarif` and `--sarif-out`, and the exit codes `--fail-on` sets: `tests/test_cli.py`,
  `tests/test_cli_characterization.py`, `tests/test_cli_errors.py`, `tests/test_sarif.py`.
  Files that cannot be read as text are reported, not passed: `tests/test_coverage.py`.
  The README's sample outputs are real runs, regenerated and compared by
  `tests/test_docs.py`; every `frisk` line in its bash fences is run, with the exit code it
  states, by `tests/test_readme_commands.py`.
- **Auditing MCP configs** (`--mcp-config`, or a config named as a target): servers frisk
  cannot read (remote, uncached packages) are reported as not scanned, never as clean:
  `tests/test_claude_json.py`, `tests/test_config_classify.py`, `tests/test_cache_lookup.py`.
- **Git URLs** are cloned with git's escape hatches closed (no hooks, submodules, LFS or
  symlinks): `tests/test_sources_git.py`, against a local bare repository.
- **Scan limits** (file count, file size, total bytes, deadline) and out-of-tree symlinks
  give visible findings instead of a hang or a leak: `tests/test_scan_bounds.py`,
  `tests/test_fs.py`. Every rule and scan surface runs in linear time on 1 MiB of its worst
  input: `tests/test_perf.py`.
- **`frisk lock` / `frisk verify`** pin content and report drift: `tests/test_pin.py`,
  `tests/test_pin_spec.py`, `tests/test_pin_atomic.py`, `tests/test_pin_links.py`.
- **`frisk proxy`** drops poisoned, malformed or batched tool lists, survives bytes that are not
  UTF-8 and always stops its server: `tests/test_proxy.py`, `tests/test_proxy_fail_closed.py`,
  `tests/test_proxy_shapes.py`, `tests/test_proxy_pins.py`, and `tests/test_proxy_e2e.py`
  against a misbehaving fake server (`tests/fixtures/fake_mcp_server.py`).
- **`frisk-mcp`** answers every malformed JSON-RPC request with an error and keeps serving:
  `tests/test_mcp_stdio.py`, `tests/test_mcp_server_characterization.py`, `tests/test_mcp_scope.py`.
- **The GitHub Action** runs no input as shell code (`tests/test_action.py`), and CI's
  `action-selftest` job runs it on both examples.
- **Foreman's admission contract** (`--stdin --json`, findings read by severity, rule and
  message) is replayed through `scripts/foreman-frisk-scan.sh`: `tests/test_foreman_contract.py`.
- **CI** (`.github/workflows/ci.yml`) runs the suite on Python 3.9 to 3.14 on Linux and 3.13
  on macOS, plus ruff, mypy and a coverage report. Whether the latest run is green is checked
  on GitHub, not here.
- **Local check, 2026-11-05**: `scripts/verify.sh` passed with the macOS Command Line Tools
  Python 3.9.6 and Homebrew Python 3.12, 3.13 and 3.14 (unittest on each, pytest on 3.14),
  ruff and mypy.

## What is not tested

- **Real use.** No dated use of a release is recorded yet (see the [use log](#use-log)).
- **Real MCP clients.** The proxy and `frisk-mcp` are tested against fake stdio peers, not
  through Claude Code, Claude Desktop or Cursor.
- **Network clones.** Git URLs are tested only against a local repository; no test clones
  over https or ssh.
- **The Action's SARIF upload.** The self-test sets `sarif: "false"`, so the upload to code
  scanning and an Action run on another repository have not run.
- **Publishing.** `.github/workflows/publish.yml` has never run.
- **Windows.** CI has no Windows job.

Known gaps:

- **A lockfile inside a directory it pins** is part of what it pins, so `frisk verify`
  reports DRIFT straight after `frisk lock` (`frisk lock .` then `frisk verify` shows
  `+ added: .frisk-lock.json`). `examples/continuous-verify.yml` tells users to run
  `frisk lock .`, so its scheduled check would fail at once. Found by the walkthrough
  ([docs/WALKTHROUGH.md](docs/WALKTHROUGH.md)) on 2026-11-05; not fixed. Until it is, keep
  the lockfile outside the directories it pins.

Two more, each from an independent review and each severity 2:

- Text that spells a phrase with HTML character references (`&#…;`) is matched undecoded,
  so such a spelling passes. This is one case of the threat model's first limitation (the
  pattern core can be evaded); see [docs/threat-model.md](docs/threat-model.md).
- A file is checked with `lstat` and then read, so a local process racing in that window
  could swap it for a link.

## Owner-held items

Only the owner does these ([RELEASING.md](RELEASING.md)); no ticket or agent does.

1. **Release 0.3.0**: fold `changes/`, set the version, push, publish the GitHub Release
   (which runs `publish.yml`), and move `v0` off the 0.2.0 commit.
2. **A pinned install** of the release (`frisk-scan==0.3.0` through uv or pipx), not an
   editable one.
3. **Switch on the proxy**: put `frisk proxy` in front of the MCP servers in the client's
   config ([docs/proxy.md](docs/proxy.md)).
4. **Switch on Foreman's scanner**: make the `frisk-scan` wrapper from
   `scripts/foreman-frisk-scan.sh` and put it on Foreman's PATH (README:
   [Foreman's admission scan](README.md#foremans-admission-scan-the---stdin-contract)).
5. **Keep a real-use log**: a dated line in the table below for each period of use.

## Use log

Dated lines of real use: what ran, which version, and what frisk reported. Empty until the
owner-held items above are done.

| Date | Version | What ran | Scans | BLOCK | WARN | Notes |
|------|---------|----------|-------|-------|------|-------|
