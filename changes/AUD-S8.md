### Changed: finding paths are relative to the target you name (AUD-S8)

`frisk` used to report every path relative to the target itself, so `frisk skills/`
printed `foo/SKILL.md`, two targets with the same layout produced identical paths, a
single-file target showed only its file name, and the GitHub Action's SARIF mapped to
repository files only when `targets` was `.`.

Paths now follow docs/adr/0001-finding-paths.md, in text, `--json` and `--sarif`
output and in `coverage.skipped`:

- a local directory: the target as given, normalised (no leading `./`, no `//`, `/.` or
  trailing `/`), joined
  with the in-target path, e.g. `frisk skills/` → `skills/foo/SKILL.md`; `.` is unchanged;
- a single file: exactly the argument;
- a git URL: relative to the clone (unchanged);
- `--mcp-config` servers: `name::path` (unchanged); `--text`: `<text>` (unchanged).

Paths are POSIX on every platform. The MCP server tools and `frisk lock`/`verify` are
unchanged.
