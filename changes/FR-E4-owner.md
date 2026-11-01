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
