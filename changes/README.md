# changes/: release-note fragments

A change that alters what frisk reports (verdicts, findings, output shape, exit codes, flags)
adds one fragment here, `changes/<ticket-id>.md`, starting with a `###` heading such as
`### Fixed: ...`, `### Changed: ...` or `### Added: ...`. It does not edit CHANGELOG.md.

Before a release the fragments are folded into CHANGELOG.md's Unreleased section, oldest
first, each followed by a `<!-- changes/<stem>.md, added in <commit> -->` line; the folded
files are deleted and their stems listed below. tests/test_version.py checks that no file
here is listed as folded and that every folded stem appears in CHANGELOG.md.

## Folded

- AUD-S5
- F1.03
- AUD-S8
- F1.08
- FR-E2-t9
- F1.07
- F1.04
- F1.06
- AUD-S13-redact
- F1.09
- F1.09-claude-json
- F1.10
- F1.11
- FR-E4-lock
- FR-E4-review
- FR-E4-owner
- FR-E4-final-review
- FR-FX1
- FR-FX1-review
- FR-FX1-lastfix
- FR-E5-t1
- FR-E5-t4
- FR-E5-t3
- FR-E5-t6
- FR-E5-t5
- FR-E5-t2
- FR-E5-t7
- H1.3
- H1.4
- H1.5
- F3.06
- F3.01
- F3.02
- F3.07
- F1.05
- F2.08
- FR-E7-t1
- FR-E7-t3
- FR-E7-t4
