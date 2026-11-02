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
