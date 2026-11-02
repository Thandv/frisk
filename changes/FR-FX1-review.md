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
- A URL is pinned by the host a client connects to. WHATWG URL parsers (node, so Claude Code
  and npm), pip and uv end the host of an http(s) URL at a backslash, which Python's
  `urlsplit` does not, so `https://evil\@pypi.org/simple` was pinned (and a server URL shown)
  as `pypi.org`: swapping an index, find-links or server URL to another host this way was
  not drift. Such a URL is now `<unparsable URL>`, pinned by its length class (the change
  from a plain URL is drift), and never shown with the host frisk would have guessed. A
  server URL with an `@` only after its host (`https://server.smithery.ai/@owner/server/mcp`,
  an email in the query) was pinned only by its length class since FR-FX1 10, so another
  host or owner of the same length class was no drift; it is pinned by host and path again,
  which hashes exactly as main did when it has no query or fragment.
- A `GIT_CONFIG_*` value is pinned as written (after the redaction, which drops a URL's
  `user:token@`), no longer word by word like a package index. Git runs some of these values
  through the shell (`core.sshCommand`, a `!` credential helper), and the word rule dropped a
  URL's query and pinned a word it could not read (a quoted URL, `SRC=https://…`) only by its
  length class, so a command hidden there was not drift. A server that sets one, locked
  before, reports DRIFT once naming it: lock again.
