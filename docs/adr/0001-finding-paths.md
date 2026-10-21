# ADR 0001: the path contract for findings, skipped entries and SARIF

Status: accepted (FR-E2). Implemented by FR-E2 t3 (coverage), t4 (paths) and t5 (SARIF).

## Context

Before FR-E2, `frisk` scanned every target with the target itself as the root, so
`frisk skills/` reported `foo/SKILL.md` instead of `skills/foo/SKILL.md`, two targets
with the same layout produced the same paths, a single-file target reported only its
base name, and SARIF from the GitHub Action mapped to repository files only when
`targets` was `.`. `--mcp-config` findings were rewritten in place to `name::path`
(cli.py), which is neither a path on disk nor a valid SARIF URI.

## Decision

The engine (`engine.scan_path`) always returns **in-target** paths: POSIX, relative
to the scanned root (for a single file, its file name). Turning those into the paths
a user sees is done in exactly one place:

**`frisk.engine.reroot(result, prefix, origin)`** rewrites every finding path, every
`coverage.skipped[].path`, and therefore every `coverage.*` finding path, as
`prefix + in-target path`, and records the finding's `origin` (`local`, `git`,
`mcp`, `text`), which SARIF uses to pick the location form. No other code edits a
finding path. `engine.display_prefix(target, is_file)` computes the prefix for a
local target; the other prefixes are constants given by the caller (`''` for a git
clone, `name::` for an MCP server).

| Target kind | (a) finding path, text and JSON | (b) `coverage.skipped[].path` and `coverage.*` findings | (c) SARIF location | (d) "every uri exists on disk relative to cwd" holds |
|---|---|---|---|---|
| local dir `.` (also `./`) | in-target path, no prefix: `foo/SKILL.md` | same rule as (a) | `uri` = (a); no `uriBaseId` | yes |
| local dir `examples`, `examples/`, `./examples` | the target normalised (`posixpath.normpath`: no leading `./`, no `//`, `/.` or trailing `/`; `a/../b` becomes `b`, which can differ from the filesystem's view if `a` is a symlink), then `/`, then the in-target path: `examples/foo/SKILL.md` for all three spellings | same rule as (a) | `uri` = (a) | yes |
| local dir, absolute (`/abs/examples`) | `/abs/examples/foo/SKILL.md` (the target as given) | same rule as (a) | `uri` = (a) made relative to cwd (`os.path.relpath`, POSIX; if that climbs out of cwd but the resolved paths do not, the resolved form), e.g. `examples/foo/SKILL.md` or `../x/SKILL.md` | yes |
| single local file (`examples/foo/SKILL.md`, `./a.py`) | the argument verbatim | same rule as (a) | `uri` = (a); an absolute argument is made relative to cwd as above | yes |
| git URL (`https://host/o/r.git`) | clone-relative path: `foo/SKILL.md` | same rule as (a) | `uri` = (a) with `uriBaseId: "SRCROOT"` | no: the clone is deleted after the scan |
| `--mcp-config` server entry | `name::` + server-relative path: `my-server::tools.py` (a server given as one file: `name::file.py`) | same rule as (a) | no physical location; a `logicalLocations` entry with `fullyQualifiedName` = (a) | no |
| `--text '<string>'` | `<text>` | not applicable: no files, so no skipped entries and no coverage findings | no physical location; a `logicalLocations` entry with `fullyQualifiedName` `<text>` | no |
| `mcp_server.py` tools (`scan_text`, `scan_artifact`, `vet_mcp_server`) | unchanged: `<text>`, or the root-relative path (a single file: its name) | same rule as (a) | not applicable: the MCP server emits JSON, never SARIF | not applicable |
| `pin.py` (`frisk lock` / `verify`) | not applicable: pin reports entries and per-file hashes, not findings; its keys are unchanged | not applicable | not applicable | not applicable |

Rules shared by every row:

- Paths are POSIX (`/`) on every platform; the in-target part comes from
  `Path.as_posix()`. A single-file argument is kept verbatim, so it keeps the
  separators the user typed.
- The uri-exists check (column d) applies only to local targets (`.`, a local dir, a
  single local file), and only when SARIF is produced from the same cwd as the scan.
- Every SARIF `uri` for a local target is relative: no absolute paths appear in SARIF
  for local targets. JSON and text show what the user typed, absolute or not.

## Departures from the proposed default, with reasons

1. **`--mcp-config` in SARIF has no physical location** (the proposal was "the server
   ref rebased like a local target"). A server's source comes from a client config and
   usually lives outside the repository (often under the user's home directory). A
   rebased path would put an absolute local path, or a `../..` path, into a file that
   is uploaded to GitHub, and code scanning could not map it to a repository file
   anyway. The finding keeps its `name::path` identity as a SARIF logical location,
   the same treatment `--text` gets.
2. **Absolute local targets keep the absolute path in text and JSON** but not in SARIF.
   The proposal's "target as given" applies to (a); (c) must stay relative so the
   SARIF is portable and deterministic.

## Consequences

- `frisk skills/ --sarif` now emits `skills/foo/SKILL.md`, so the GitHub Action maps
  findings to repository files for any local `targets` value, not only `.`.
- Two sibling targets never collide: their prefixes differ.
- `--mcp-config` and `--text` results appear in SARIF consumers that read logical
  locations; GitHub code scanning may not display results without a physical
  location. The text and JSON output always show them.
- A later surface or coverage reason never edits paths: it returns in-target paths
  and `reroot` does the rest.
