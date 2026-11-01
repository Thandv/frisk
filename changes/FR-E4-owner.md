### Changed: owner decisions on the FR-E4 review's open items

- **A command beside a url is scanned (N1).** An entry with both a `command` and a `url`
  (or `serverUrl`), whatever its `type`, used to be classified as remote, so a decoy URL
  kept the command's script from being read (a pipe-to-shell installer passed as WARN, or
  PASS before FR-E4). The command is now classified and scanned like any other server, so
  it can BLOCK, and the entry also raises a `coverage.unscanned` warning that it names a
  remote URL, which frisk does not scan. The text line and the JSON `reason` name the URL
  (redacted like every URL). An entry with only a `url` is still a remote server.
- **Code-loading env values are pinned (N2).** `frisk lock` pinned only the names of a
  server's env variables, so changing `NODE_OPTIONS` from empty to
  `--require /tmp/evil.js` was not drift. The values of these variables are now pinned, as
  sha256 hashes in the lockfile: `NODE_OPTIONS`, `NODE_PATH`, `PYTHONPATH`, `PYTHONSTARTUP`,
  `PYTHONHOME`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_INSERT_LIBRARIES`, `DYLD_LIBRARY_PATH`,
  `DYLD_FRAMEWORK_PATH` and any other `DYLD_*`, `PERL5OPT`, `PERL5LIB`, `RUBYOPT`, `RUBYLIB`,
  `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`, `BASH_ENV` and `ENV`. A changed value is DRIFT;
  `frisk verify` prints `~ NODE_OPTIONS changed` (JSON: `"env": ["NODE_OPTIONS"]`) and never
  the value. Every other env value stays unpinned, so rotating a secret is still not drift.
  A lock entry written before this change for a server that sets one of these variables
  reports DRIFT once with that line: lock again. Other entries verify as before.
- **URLs are shown by their host only (N3).** Every URL frisk prints from a config, in the
  text report, `--json`, `--sarif`, `-q`, `frisk verify` and debug lines, is now
  `scheme://host[:port]`, plus `/…` when anything followed the host
  (`https://mcp.example.com/…`). The path used to be shown, and some hosted MCP providers put
  the access key in it (`/mcp/<key>/sse`), as do session parameters (`;jsessionid=…`). A URL
  whose host part holds anything but a host name or address is `<unparsable URL>`, as are
  the DEFECT-1 shapes. `frisk lock` still pins the path (without credentials, query or
  fragment), so a changed endpoint is still drift and existing lockfiles verify as before.
- **A console-script wrapper is not passed on itself (N4).** A `command` that is a small
  generated wrapper (pip, pipx and uv write a few lines that import a package's entry point
  and call it in `sys.exit(...)`; `uv tool install` links it into `~/.local/bin`), a shell
  shim that execs node (pnpm, cmd-shim), or a file inside a node package (where an npm bin
  link points) used to be scanned as that one file and PASS, while the package that really
  runs was never read. Such a server is now kind `wrapper`: not scanned, a
  `coverage.unscanned` warning naming the package (`console-script wrapper or bin shim for
  the Python package 'acme_mcp', which frisk does not scan`), so WARN, never PASS. The
  wrapper file itself is still read, so a payload hidden in it BLOCKs. Larger scripts, and
  scripts that call a function they define themselves, are scanned as before.
- **A config with no servers warns (N5).** A config in which frisk found no servers printed
  `(no servers found in config)`, `frisk: clean` and PASS, also when it was a format frisk
  does not read. New warn rule `coverage.no_servers`: such a config is WARN with `no MCP
  servers found in <file> (frisk reads 'mcpServers' and 'servers', at the top level and in
  each 'projects' entry)`, as a target and with `--mcp-config`, in every output format
  (`--fail-on warn` exits 1). No config format was added: VS Code's `settings.json`
  (`mcp.servers`), Zed's `context_servers` and a misspelt `mcpservers` are still not read,
  and now say so. The text report also escapes a finding's description, which can now
  carry a file name.
