### Changed: `frisk lock` pins an MCP config per server, never as a whole file (FR-E4, owner decision)

- `frisk lock ~/.claude.json`, or any MCP config named as a target, used to pin the file's
  bytes, so every unrelated change Claude Code makes to the file was DRIFT. A config named
  as a target is now pinned exactly like `--mcp-config` (the same entries), and a config
  named twice is pinned once.
- Per config: one entry, `<config>` (kind `mcp-config`), lists its server names, so an
  added or removed server is DRIFT.
- Per server: `<config>::<name>` pins how it starts (command, args, cwd, type, the URL
  without credentials, query or fragment, and the names, not the values, of its env vars
  and headers) together with the code frisk scans for it: local source, or a cached package
  with its version. `frisk verify` shows a changed launch as `~ changed: how it starts
  (command, args, cwd, URL, env or header names)`, and `--json` adds `"launch": "changed"`.
  Rotating an env value, a header value or a URL token is not drift.
- Older lockfiles keep the checks they were written with. A config that an older frisk
  pinned as a whole file verifies while the file is unchanged; after that, `frisk verify`
  reports one error (exit 1), `MCP config pinned as a whole file by an older frisk: run
  frisk lock again to pin each server`, never a traceback.
