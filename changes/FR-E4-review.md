### Fixed: holes found by the independent review of the MCP config audit (FR-E4)

- A config that holds both `mcpServers` and `servers` is audited whole. Claude Code runs
  `mcpServers` and VS Code runs `servers`; frisk used to read `servers` only when
  `mcpServers` was missing, so an empty `"mcpServers": {}` hid every VS Code server (main
  read `servers` when `mcpServers` was empty, so this was a BLOCK-to-PASS regression). A
  name found in both maps is listed twice, the second as `name (servers)`.
- A cached Python package that installs a script of its own into its environment's `bin/`
  (a wheel's `.data/scripts` file, which `uvx` and `pipx` run as the command) is skipped as
  `local cache entry unusable (...)` instead of passing on its package directory alone:
  frisk scans only the package, so such a server used to PASS with a pipe-to-shell
  installer in the script that actually runs. Wrappers generated for the package's own
  entry points (`entry_points.txt`) are accepted as before.
- `$HOME` and the directories above it are recognised with symlinks resolved. The guard
  compared paths as written, so a symlink to `$HOME` (one committed in a repo, or a `$HOME`
  that is itself a link) made the walk-up or a directory argument scan all of `$HOME`,
  printing excerpts of whatever matched there.
- The text report also escapes control characters in a finding's excerpt (the scanned line,
  which a malicious package writes: cursor moves, line erases, an OSC 52 clipboard write or
  'conceal' could hide its own BLOCK line), in the target names on the verdict and `-q` lines
  and in error messages (a project key). A lone surrogate in a server name (valid JSON) is
  shown as `\ud800`; it used to stop the text and `--sarif` reports with a traceback and
  `frisk lock` with exit 2.
