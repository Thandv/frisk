### Added: `--stdin`, and a `message` field in `--json` findings (FR-E7 t3)

- `frisk --stdin` scans text read from standard input, labelled `<stdin>`, as `--text`
  scans a string. It reads at most `--max-file-bytes` bytes (default 2 MiB, 2097152);
  longer input is read only that far and raises the warning `coverage.truncated`
  ("standard input is over the N-byte limit: only its first N bytes were read and
  pattern-matched"), so it is never PASS. A multi-byte character cut at the limit is left
  out. Input that is not valid UTF-8 is scanned with the bad bytes replaced and raises
  `coverage.unreadable`; it never ends in a traceback. Empty input is PASS.
- Each finding in `--json` output gains `message`, equal to its `description` (additive:
  every other key is unchanged). Foreman's admission scan reads `message`.
- `scripts/foreman-frisk-scan.sh` is a template, installed nowhere, for a `frisk-scan`
  wrapper: it runs the frisk command given as its first argument with `--fail-on never`
  and the remaining arguments. frisk still ships only the `frisk` and `frisk-mcp` commands.
- The README and LAUNCH.md install lines now read `uvx --from frisk-scan frisk` and
  `pipx run --spec frisk-scan frisk` (`uvx frisk-scan` and `pipx run frisk-scan` named a
  command that does not exist).
