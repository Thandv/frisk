### Fixed: holes found by the review of the FR-E4 follow-ups (FR-FX1)

- Auditing a config takes linear time again. Since every value of every server passes
  through frisk's redaction when the config is parsed (for `frisk lock`), and the redaction
  read a key/token/secret/password/authorization/cookie name from each place one starts,
  rescanning the rest of the word each time, one long argument made of such names with no
  `=` (`keykeykey…`) took quadratic time: 64 KiB made `frisk --mcp-config` take 49 s (main:
  0.16 s) and 1 MiB about three hours, in a scan, `frisk lock` and `frisk verify` alike. A
  name is now matched from the start of its word, which is read once; the same values are
  redacted.
