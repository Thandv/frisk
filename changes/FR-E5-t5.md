### Changed: scans are bounded, and a bound that is hit is a visible warning (FR-E5 t5)

- A file larger than `--max-file-bytes` (new flag; default 2 MiB, 2097152 bytes) is no
  longer read: it is listed in coverage with reason `too_large` and raises the new
  block-severity finding `coverage.too_large`, so the scan fails under the default
  `--fail-on block` (and the Action's default): a script padded past the limit must not
  pass a gate that would block it whole. Raise `--max-file-bytes` to scan such a file, or
  leave it out of the target. frisk used to read every file whole, whatever its size.
- A directory target is walked one directory at a time in name order (it used to be listed
  whole first) and the walk stops after 20,000 files with a `coverage.unscanned` warning
  (reason `file_cap`) at the target. The engine's `ScanLimits` can also stop it at a byte
  total (`byte_cap`) or a time limit (`deadline`); frisk-mcp uses those (FR-E5 t7).
- Text over the limit (`--text`, frisk-mcp `scan_text`, the proxy's tool descriptions and
  results; 2 MiB characters, or `--max-file-bytes` for `--text`): the rules run on its first
  and last halves of the limit (line numbers count from the start of the whole text), the
  hidden-Unicode check on all of it, and a new warning, `coverage.truncated`, says so. This
  replaces the ask's "scan the first cap bytes": a payload placed at the end is still found.
- `coverage.unscanned` now also covers trees left unscanned by a limit; its description in
  SARIF says so.
