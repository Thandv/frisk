# Releasing frisk

Every step here is **owner-only**. No ticket, agent or CI job runs them; the publish
workflow runs only when the owner publishes a GitHub Release.

The version lives in one place, `__version__` in `src/frisk/__init__.py`; `pyproject.toml`
reads it through hatch (`dynamic = ["version"]`, `[tool.hatch.version]`). PyPI has 0.1.0
only. 0.2.0 was tagged but is never uploaded: its proxy fails open. The next release is
0.3.0.

## Steps for a release (0.3.0 as the example)

1. **Fold the remaining fragments.** Move every `changes/*.md` other than `changes/README.md`
   into CHANGELOG.md's Unreleased section (oldest first, each followed by its
   `<!-- changes/<stem>.md, added in <commit> -->` line), delete those files, and list their
   stems under `## Folded` in `changes/README.md`.
2. **Set the version.** `__version__ = "0.3.0"` in `src/frisk/__init__.py`, and give the
   CHANGELOG heading its date: `## 0.3.0 — YYYY-MM-DD`.
3. **Test.** `python3 -m pytest -q` and `bash scripts/verify.sh`; `ruff check`.
4. **Push** `main` to GitHub and wait for a green CI run.
5. **GitHub Release.** Create the release with tag `v0.3.0` on that commit. Publishing it
   starts `.github/workflows/publish.yml`, which uploads to PyPI through the trusted
   publisher.
6. **Move the floating `v0` tag** to the release commit (`git tag -f v0 v0.3.0`, then push
   that tag with force). Today `v0` points at the 0.2.0 commit, whose proxy fails open, and
   Action users on `@v0` run that code.
7. **Pinned install for Foreman.** A pinned, non-editable install of the released package
   (`frisk-scan==0.3.0`, through uv or pipx) gives exactly two commands, `frisk` and
   `frisk-mcp`. frisk ships no `frisk-scan` command, so installing it does not switch on
   Foreman's admission scanner.

Switching Foreman's admission scanner on is a separate owner act, done later and on purpose:
Foreman runs `frisk-scan --stdin --json` when a `frisk-scan` command is on its PATH. The
owner makes that command as a small wrapper around the installed `frisk`; the template is
`scripts/foreman-frisk-scan.sh`, which frisk installs nowhere.

## One-time setup before the first workflow release (owner-only)

`.github/workflows/publish.yml` has never run. Publishing a GitHub Release starts it: a
`test` job (`scripts/verify.sh`), then `build` (`scripts/check_tag_version.py` checks that
the tag is `v` + `__version__`, then `python -m build` and `twine check`), then `publish`
(PyPI, through trusted publishing, with attestations) and `release-assets` (attaches
`dist/*` to the Release). Before the first one:

1. **GitHub environment.** In the repository's Settings → Environments, create an
   environment named `pypi`. Optionally require the owner's approval and limit it to tags
   matching `v*`, so a publish waits for a click.
2. **PyPI trusted publisher.** On PyPI, in the `frisk-scan` project's Publishing settings,
   add a GitHub publisher with owner `Thandv`, repository `frisk`, workflow `publish.yml`
   and environment `pypi`. No API token is stored anywhere.
3. **The old publisher.** If a publisher was added earlier without an environment, remove
   it, so only this workflow and environment can upload.

The `publish` job alone gets `id-token: write` (for the trusted publisher and the
attestations) and `release-assets` alone gets `contents: write`; every other job reads only.
