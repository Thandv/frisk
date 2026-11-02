### Added: frisk-mcp scope limits (FR-E5 t7)

`scan_artifact('/')` used to scan the whole disk synchronously, holding frisk-mcp for hours.

- `scan_artifact` and `vet_mcp_server` now stop after 20,000 files, 200 MiB read or 30 s
  (and skip files over 2 MiB), returning what they found. Any incomplete result (a limit, a
  skipped file, text over the limit) adds `"degraded": true` and `"coverage":
  {"files_scanned": N, "skipped": {reason: count}}` to the JSON.
- New `FRISK_MCP_ROOTS` (an os.pathsep-separated list): a local path outside these
  directories is refused; symlinks and `..` are resolved first.
- New `FRISK_MCP_NO_NETWORK=1`: git URLs are refused before git runs.
- `/`, `$HOME` itself and `/System` are refused unless named in `FRISK_MCP_ROOTS`.
- A refusal is an `isError` result with a one-line reason. Results still never include
  excerpts.
