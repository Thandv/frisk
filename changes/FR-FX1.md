### Fixed: follow-ups from the FR-E4 reviews (FR-FX1)

- A server whose `command` is a regular file named `node_modules` no longer ends the whole
  audit, and `frisk lock`, in a traceback (an `IndexError`, exit code 1, no `--json`
  output). The file is classified and scanned like any other command file; a file inside a
  node package (`node_modules/acme/…`) is still a wrapper for that package.
- Telling whether a target is a git URL takes linear time. The `git@<host>:<path>` check
  tried a split at every `:`, so a long target took quadratic time (20,000 characters about
  2 s, 1 MiB one to two hours). `frisk verify` checks each lockfile target this way, so a
  committed lockfile could stall CI; a CLI target and a `frisk-mcp` source could too. The
  same strings are accepted as before.
- The `github.com/owner/repo` shorthand loses its query and fragment like a full git URL.
  It is cloned as `https://github.com/owner/repo…`, but only targets holding `://` lost
  them, so `github.com/o/r?t=<token>` was printed in the report label (text, `--json`,
  `-q`), stored in the lockfile (key and value), echoed in git's failure message and
  returned as `frisk-mcp`'s source. The clone still uses the target as given; `frisk verify`
  re-clones the clean one. A local path that happens to start with `github.com/` is
  unchanged.
- `frisk lock` also pins the values, as hashes, of `LD_AUDIT`, `GIT_SSH_COMMAND`,
  `GIT_EXEC_PATH`, `npm_config_registry`, `NPM_CONFIG_REGISTRY`, `PIP_INDEX_URL`,
  `PIP_EXTRA_INDEX_URL`, `UV_INDEX_URL`, `UV_EXTRA_INDEX_URL` and `UV_DEFAULT_INDEX`. Each
  decides what code runs (an audit library loaded like `LD_PRELOAD`, the program git runs
  for ssh, where git finds its own programs, the index npm, pip or uv installs a package
  from), but a changed value was not drift. A changed value is now DRIFT, named as
  `~ PIP_INDEX_URL changed`, never shown. `PATH` is deliberately not pinned: it differs
  between shells and machines, so every lock would drift. A lock entry for a server that
  sets none of these is unchanged and verifies as before; one written before this change for
  a server that sets one of them reports DRIFT once with that line: lock again.
- An index URL in those variables is pinned without its credentials: each URL (several may
  be separated by whitespace) by its scheme, host, port and path only, so a token in its
  `user:token@`, query or fragment is never stored, not even as a hash. Rotating the token
  is not drift; a changed host or path is. A word that is not such a URL, or whose host part
  cannot be told from a password, is pinned only as `<unparsable URL>` and its length class
  (the bit length of its length), never as written. A lock that hashed an index URL whole
  reports DRIFT once with `~ PIP_INDEX_URL changed` (or the variable it sets): lock again.
- A console-script wrapper whose own file has findings shows their verdict. The audit reads
  the wrapper (a payload in it BLOCKs), but its line said `[SKIP ]` and its `--json` entry
  `"verdict": null` while its BLOCK findings were listed, understating it for anyone reading
  per server. The line now shows `[BLOCK]` (or `[WARN ]`) and `--json` the same verdict; it
  keeps `"status": "skipped"`, its `→` location and its place in `N of M servers not
  scanned`, since the package it runs is still not read. A wrapper with no findings is
  `[SKIP ]` as before.
- `frisk lock` also pins the remaining package sources: `UV_INDEX` (uv's current index
  variable, `name=url` entries included), `PIP_FIND_LINKS` and `UV_FIND_LINKS`, npm's user
  config file (`npm_config_userconfig`, `NPM_CONFIG_USERCONFIG`) and any `GIT_CONFIG_*`
  variable (git configuration given in the environment, such as `GIT_CONFIG_KEY_0` /
  `GIT_CONFIG_VALUE_0`, which can set `core.sshCommand` or redirect a fetch with
  `url.<base>.insteadOf`). `UV_INDEX` is pinned like the other index variables, uv's index
  name included. In a find-links or `GIT_CONFIG_*` value each word holding `://` is pinned
  the same way, so a token in such a URL (`url.https://user:token@host/.insteadOf`) is never
  stored, and any other word (a local path, a git config key or option) is pinned as given.
  A server that sets one of these, locked before, reports DRIFT once naming it: lock again.
- The `github.com/owner/repo` shorthand is cloned from `https://github.com/` in any letter
  case. frisk took `GitHub.com/Acme/Tool` for a git target but passed it to git as written,
  which git reads as a local path, so the clone failed; the host is now lowercased, owner
  and repository keep their case. `frisk verify` re-clones such a pinned target the same way.
