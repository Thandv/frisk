### Fixed: the proxy survives bad bytes and never leaves its server running (FR-E5 t2)

- One byte from the server that was not valid UTF-8 ended `frisk proxy` with a traceback
  (under a UTF-8 locale). The relay now decodes without failing; the line holding such
  bytes is dropped and logged, and the next messages are relayed. Client input is relayed
  byte for byte.
- The real server is stopped (SIGTERM, then SIGKILL after 5 s) and reaped on every way the
  proxy ends. A client that stopped reading ended the proxy with a `BrokenPipeError`
  traceback and left the server running; it now logs `client gone`. SIGTERM or SIGINT to
  the proxy stops the server too. When the client closes the proxy's input, the server gets
  5 s to exit before it is stopped. The exit code is the server's status (128 + the signal
  number when a signal ended it, which `frisk proxy` used to pass on as a negative number).
- A tool result over frisk's text limit (2 MiB characters) is delivered, prefixed
  `[frisk: partially scanned — ...]`, scanned by engine.scan_text's head-and-tail policy.
  A tool over that limit is dropped instead: a payload in its unscanned middle would reach
  the model (main scanned it whole and dropped a poisoned one).
- `frisk proxy` exits 2 with one line when the server command cannot be started for any
  reason (it caught only a missing command: a file without the execute bit was a traceback)
  or when `--log` cannot be opened (also a traceback); the log file is closed on every path.
