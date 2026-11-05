### Fixed: a lockfile inside a directory it pins is not drift

`frisk lock .` then `frisk verify` reported `[DRIFT] . + added: .frisk-lock.json` at once
(and `~ changed: .frisk-lock.json` after a re-lock), because the lockfile was hashed as part
of the directory it sits in; so did a local MCP server whose directory holds the lockfile.
`examples/continuous-verify.yml`'s flow failed on its first run. The regular file at the
lockfile's own path (`--lockfile`, by its resolved directory and exact name) is now left out
of every tree `frisk lock` pins and `frisk verify` recomputes. A file of the same name
anywhere else in the tree, or a link at the lockfile's path, is still pinned.

A lock written before this with the lockfile inside a pinned directory, after a second
`frisk lock`, reports DRIFT once with `- removed: .frisk-lock.json`: run `frisk lock` again.
A lock written by a first `frisk lock` (no lockfile in the tree yet) now verifies clean.
Locks whose lockfile is outside every pinned tree verify as before.
