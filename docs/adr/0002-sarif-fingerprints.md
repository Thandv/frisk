# ADR 0002: SARIF partial fingerprints

Status: accepted (FR-E2 t5; reviewed in FR-E2 review 5).

## Decision

Every SARIF result carries `partialFingerprints["frisk/v1"]`, the sha256 hex digest of
four NUL-separated fields:

1. the rule id;
2. the result's path: the SARIF `uri` for a physical location (cwd-relative for local
   targets, clone-relative for git URLs), or the logical name (`<text>`, `name::path`);
3. the source line of the match, trimmed, with each run of internal whitespace collapsed
   to one space (`report.normalise_line`);
4. the occurrence index: how many earlier results, in the report's (path, line, rule)
   order, have the same first three fields (`0` for the first).

The line number is not an input, so inserting or deleting lines above a finding keeps its
fingerprint (`tests/test_sarif.py`).

## Why the occurrence index stays

The reconciled must-fix for t5 names rule, path and trimmed line only; t5's full prompt
adds the occurrence index. On the merits the index stays:

- **Uniqueness.** Without it, two copies of one flagged line in one file (a payload
  pasted twice, or the same instruction repeated in a long prompt) get the same
  fingerprint. A code-scanning service that matches alerts by fingerprint then sees one
  alert, so the second copy can stay hidden after the first is removed, and a copy
  added later raises no new alert. GitHub's own upload action solves the same problem
  the same way: its line-hash fingerprint ends in a per-file occurrence counter.
- **Stability.** Adding a line that differs in rule, normalised text or file shifts no
  index, so no existing fingerprint changes. Adding another copy of a flagged line
  changes which of the identical copies holds index 0, but the copies are
  indistinguishable by content, so the old fingerprints all remain and exactly one new
  one appears: one new alert for one new finding
  (`test_an_added_duplicate_only_adds_a_fingerprint`). Removing a copy removes one
  fingerprint, the highest index.

Collapsing internal whitespace (rather than only trimming) is kept for the same reason:
re-indenting or re-spacing a line keeps its alert. Two lines that then normalise alike are
told apart by the index.

## Consequences

- The fingerprint changes when the flagged line's text changes (beyond whitespace), when
  the file moves, or when the scan runs from a different directory for an absolute local
  target (its `uri` is cwd-relative). In CI the scan runs from the repository root.
- A bump of any input's definition must change the key name (`frisk/v2`), not reuse
  `frisk/v1`.
