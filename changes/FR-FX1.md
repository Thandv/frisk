### Fixed: follow-ups from the FR-E4 reviews (FR-FX1)

- A server whose `command` is a regular file named `node_modules` no longer ends the whole
  audit, and `frisk lock`, in a traceback (an `IndexError`, exit code 1, no `--json`
  output). The file is classified and scanned like any other command file; a file inside a
  node package (`node_modules/acme/…`) is still a wrapper for that package.
