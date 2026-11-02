### Fixed: holes found by the review of the FR-E4 follow-ups (FR-FX1)

- Auditing a config takes linear time again. Since every value of every server passes
  through frisk's redaction when the config is parsed (for `frisk lock`), and the redaction
  read a key/token/secret/password/authorization/cookie name from each place one starts,
  rescanning the rest of the word each time, one long argument made of such names with no
  `=` (`keykeykey…`) took quadratic time: 64 KiB made `frisk --mcp-config` take 49 s (main:
  0.16 s) and 1 MiB about three hours, in a scan, `frisk lock` and `frisk verify` alike. A
  name is now matched from the start of its word, which is read once; the same values are
  redacted.
- A change next to a secret in a pinned value is drift again. FR-FX1 10 hashed each value
  after redacting it, and a redacted secret ran to the next whitespace (in a URL, over
  anything but `/?#` up to the last `@`), so a change inside that span was not drift, while
  the span could hold what decides what runs: a shell command after `;` or in `$(…)`
  (`GIT_SSH_COMMAND="ssh -o StrictHostKeyChecking=no;…"`, a credential helper's
  `password=$(…)`, `sh -c "API_KEY=x;…"`), every later entry of a path list after a
  directory named like a key (`PYTHONPATH=/srv/tokenizers:/srv/app`), the library ssh loads
  (`SecurityKeyProvider=…`), an option after `token=basic ` (`-javaagent:…`), the rest of a
  compact JSON argument, a host after a backslash. Each of these was DRIFT on main or before
  FR-FX1 10. There a secret now ends at the first character other than a letter, a digit or
  one of `_.+=%@!*-` (in a URL's `user:password@`, also `:` and `~`), and a Bearer or Basic
  credential after a name never takes an option either. A secret made of other characters
  is redacted up to the first of them; the rest is pinned. Debug lines keep the wider
  redaction.
