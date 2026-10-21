### Fixed: edge cases found by the FR-E2 QA pass (FR-E2 t9)

- A leading UTF-8 byte-order mark is treated as encoding, not content: a file with a
  BOM scans exactly like the same file without it (before, a rule anchored at the
  start of the file missed its first line, and excerpts began with U+FEFF).
- A subdirectory that cannot be listed is no longer silently left out: it is recorded
  in `coverage.skipped` as `unreadable` and raises a `coverage.unreadable` warning.
- A target named twice (`frisk skill skill`, `frisk skill ./skill/`, or a relative and
  an absolute spelling of the same path) is scanned once instead of doubling every
  finding, count and skipped entry. The verdict line still lists the targets as typed.

Deferred to FR-E3a (markdown surface): unclosed ``` fences, ~~~ fences, and a longer
backtick fence that contains a shorter one are not yet scanned as code.
