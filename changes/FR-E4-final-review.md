### Fixed: holes found by the final review of the MCP config audit (FR-E4)

- Every server in a config has a name of its own. A top-level server could be named like a
  project server (`db (~/work/app)`), and two spellings of one project path share a label;
  `frisk lock` pins a server by its name and `frisk verify` finds it by that name, so after
  a project server was locked, changing it and adding a top-level copy of its old entry under
  its name made `frisk verify` report no drift. A name an earlier server already has is now
  followed by ` (2)`, ` (3)`, ..., so the extra server shows as added (DRIFT), and a config
  that really holds such names verifies cleanly right after `frisk lock`.
- A git clone that does not finish within two minutes stops with `git clone timed out after
  120 s` (exit code 2 for a scan or `frisk lock`, an error entry in `frisk verify`). It used to
  end in a traceback whose message was the whole git command, so the token in a git URL was
  printed after all, also in `frisk verify`'s error detail (for a lockfile an older frisk
  wrote with the token) and in `frisk-mcp`'s error text.
- A malformed `url`, `serverUrl` or `cwd` beside a `command` no longer hides the command.
  Such an entry was `invalid` and its command was never read, so a pipe-to-shell installer
  next to `"url": 0` or `"cwd": 7` was WARN (exit 0 under the default `--fail-on block`)
  where main said BLOCK; Claude Code runs the command and ignores both keys. The command is
  now classified and scanned as usual; a `url` that is not a string warns as
  `<unparsable URL>`, and a `cwd` that is not a string is ignored, as when it is missing. An
  entry with no command and such a `url` is still `invalid`.
- Console-script wrappers in the other forms pip and uv write are not passed on themselves
  either: a wrapper started through `/bin/sh` (its second line runs Python with `'''exec'`,
  which pip and uv write when the interpreter's path is over the shebang limit or holds a
  space, and uv for a relocatable environment) and a wrapper for an entry point
  `module:Object.method` (`sys.exit(Object.method())`). Both were scanned as one file and
  PASSed while the package that runs was never read; they are now `wrapper` and WARN, and
  the wrapper file itself is still read.
