### Fixed: holes found by the last-fix review of the FR-FX1 review's on-top

- A URL with a backslash in its host part is pinned by the host clients connect to. The
  review's on-top pinned such a URL only as `<unparsable URL>` and its length class, but
  node (so Claude Code and npm), uv and pip end an http(s) host part at a backslash:
  `https://mcp.example\sse` is fetched from `mcp.example`. So a config that already held one
  (a server url, an index, registry or find-links variable) could swap its host for any
  other of the same length class with no drift, where FR-FX1 10 had pinned it as written.
  The host part now ends where those clients end it and the backslash stays in the path, so
  a changed host or path is drift again, and a token in its `user:token@` is still never
  stored. The audit still shows such a URL as `<unparsable URL>`. A server that sets one,
  locked before, reports DRIFT once: lock again.
- A changed version pin is drift again when the package's name holds a key, token,
  secret, password, authorization or cookie name. Since FR-FX1 10 a value after such a name
  and `=` is redacted before it is hashed, and the name is found anywhere in a word, so
  `mcp-keycloak==1.0.0`, `tiktoken==0.7.0` or `keyring==24.0` (in `uvx --from`, `uv run
  --with`, `pipx run --spec`, a `pip install` in `sh -c`) was pinned without its version,
  and changing the version, which decides what code runs, was not drift where the package
  was not in the local cache (as in CI). A name followed by `==` is no longer read as the
  start of a secret; `--api-key=…`, base64 padding after it and `PASSWORD:=…` are
  redacted as before. A server holding such a pin, locked before, reports DRIFT once: lock
  again.
