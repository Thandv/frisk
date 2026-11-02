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
