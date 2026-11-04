### Changed: `frisk --help` lists every subcommand and the exit codes (FR-E7 t4)

`frisk --help` now ends with the subcommands (scan, `lock`, `verify`, `proxy`) and the exit
status of a scan: 0 when no finding reached the `--fail-on` level (always 0 with
`--fail-on never`), 1 when the worst finding reached it, 2 for a usage error, no target, or
a target, MCP config, `--stdin` or `--sarif-out` file that cannot be read or written; and
how `lock` (0 or 2), `verify` (0; 1 on drift or an entry it could not verify; 2 on a
lockfile it cannot read) and `proxy` (the server's status, or 2) exit. The description is no
longer re-wrapped to the terminal width.

A target, MCP config, lockfile, `--sarif-out` file or `--log` file that is a directory or
cannot be read (PermissionError, IsADirectoryError) already exits 2 with one stderr line
and no traceback; tests/test_cli.py now checks it for each subcommand.
