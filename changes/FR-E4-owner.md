### Changed: owner decisions on the FR-E4 review's open items

- **A command beside a url is scanned (N1).** An entry with both a `command` and a `url`
  (or `serverUrl`), whatever its `type`, used to be classified as remote, so a decoy URL
  kept the command's script from being read (a pipe-to-shell installer passed as WARN, or
  PASS before FR-E4). The command is now classified and scanned like any other server, so
  it can BLOCK, and the entry also raises a `coverage.unscanned` warning that it names a
  remote URL, which frisk does not scan. The text line and the JSON `reason` name the URL
  (redacted like every URL). An entry with only a `url` is still a remote server.
