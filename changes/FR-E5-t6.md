### Fixed: frisk verify tells drift from entries it could not verify; git never prompts (FR-E5 t6)

- `frisk verify` counted an entry it could not verify (a target that is gone or cannot be
  cloned, an old whole-file config pin) as drift and printed `DRIFT DETECTED`. Such an entry
  is now counted apart: the summary is `verify: could not verify N entries  (0 of M entries
  changed)`, or `verify: DRIFT DETECTED  (D of M entries changed; could not verify N entries)`
  when there is drift too. The exit code is still 1 in both cases.
- A lockfile that is not a JSON object with an `entries` object (a list, no `entries`)
  ended `frisk verify` with a traceback, or verified as `no drift`; it now exits 2 with one
  line. One malformed entry (not an object, no digest) is reported as `[error] ... not a
  valid lockfile entry` and the other entries are still verified.
- `git clone` runs with stdin closed and `GIT_TERMINAL_PROMPT=0`, so it can never wait for
  a credential prompt; the rest of the environment is passed on unchanged.

Already so since FR-E4, and now covered by tests/test_cli_errors.py: a clone that times out,
a config whose top level, `mcpServers` or `projects` is a list, and an unreadable file named
to `frisk lock` each exit 2 with one line.
