# Changelog

Each change that alters what frisk reports, its output shape or its exit codes lands with a
fragment in `changes/`; fragments are folded into this file before a release (see
`changes/README.md` and `RELEASING.md`). PyPI package: `frisk-scan`.

## 0.3.0 — Unreleased

The next release. `src/frisk/__init__.py` still says `0.2.0` until the owner sets the
version as the first release step (RELEASING.md). 0.2.0 is skipped on PyPI: its proxy fails
open.

Highlights, each detailed in the entries below:

- **Verdicts.** A scan is never PASS while something went unscanned: an MCP server frisk
  could not scan (`coverage.unscanned`, F1.11), executable or archive content
  (`coverage.binary`) and unreadable or non-UTF-8 files (`coverage.unreadable`, F1.03), a
  scan stopped by a limit, and text over the size limit (`coverage.truncated`); a file over
  `--max-file-bytes` is not read and blocks (`coverage.too_large`, FR-E5 t5). A symlink
  leading outside the scanned tree is `fs.symlink_escape`, blocking when it points at a
  credential location (H1.3). Rule precision and the markdown, build-recipe and JSON
  surfaces change which lines match (F1.04, F1.05, F1.06, F1.07).
- **SARIF.** Byte-identical across runs; `artifactLocation.uri` is POSIX and relative to the
  current directory for local targets, git-URL results use `uriBaseId: "SRCROOT"`, and
  `--text` and MCP-config results use logical locations; `partialFingerprints["frisk/v1"]`
  and `helpUri` per rule (F1.08).
- **Lockfile.** Still version 1, and any other version is refused (exit 2). A tree holding
  symlinks gets a new digest (links are pinned by where they point): run `frisk lock` again;
  trees without symlinks keep theirs (H1.3, F3.07). An MCP config is pinned per server
  (FR-E4).
- **Coverage.** Every format reports what was not pattern-matched: the text line `scanned N
  files, skipped M (...)`, `coverage` in `--json`, `runs[0].properties.coverage` in SARIF
  (F1.03).
- **Proxy.** `frisk proxy` fails closed (FR-E5 t1), survives bad bytes and never leaves its
  server running (FR-E5 t2), inspects every server-to-client shape (F3.01), keeps pins of the
  whole tool definition across runs (F3.02) and judges descriptions and results by context
  (F2.08).

### Entries

<!-- entries -->
### Fixed: findings inside markdown code fences report their file line (AUD-S5)
<!-- changes/AUD-S5.md, added in 4dda789 -->

A finding inside a ```` ``` ```` fence used to be reported at its line within the fence
(the pipe-to-shell installer in `examples/malicious-skill/SKILL.md` showed as line 1).
It is now reported at its line in the file (line 11), in text, `--json` and `--sarif`
output, so GitHub code-scanning annotations land on the right line.

Line numbers are now looked up in a per-file line index, so files with many matches
no longer slow down quadratically.

Internally the engine runs its rules on "surfaces" (`src/frisk/surfaces/`): `plain`
(the whole file) and `fences` (code fences in non-code files). A surface that fails on
a file no longer stops the scan; the rest of the file and every other file are still
scanned, and the failure is recorded in the scan's coverage.

### Added: visible coverage; unscannable executables and unreadable files now warn (F1.03)
<!-- changes/F1.03.md, added in 49c889c -->

Every scan now reports what it did not pattern-match.

- Text output prints `scanned N files, skipped M (<reason>: <count>, ...)` above the
  verdict line (not for a `--text`-only scan). `--json` gains a `coverage` object
  (`files_scanned`, `skipped: [{path, reason, detail}]`); `--sarif` carries the same
  object in `runs[0].properties.coverage`. Several targets are totalled.
- New warn rule `coverage.binary`: executable content frisk cannot read as text
  (ELF/Mach-O by magic bytes, only on a non-UTF-8 file with no code/text extension or
  shebang; `.so`, `.dylib`, `.dll`, `.wasm`, `.exe`, `.node`,
  `.pyc`, `.pyo`, `.jar`, `.class`) and archives (`.zip`, `.tar`, `.gz`, `.tgz`,
  "contents unscanned"). These used to be dropped silently, so a directory holding
  only a native binary scanned as PASS; it is now WARN.
- New warn rule `coverage.unreadable`: a file that cannot be read or is not valid
  UTF-8. One invalid byte used to make a file vanish from the scan and the report say
  "clean"; such a file is now scanned with the bad bytes replaced and also warns. Only
  media and opaque data (`.bin`, `.dat`, `.db`, `.sqlite`, `.npy`, `.parquet`, silent),
  executables, archives and NUL-containing files with an unlisted extension
  (`coverage.binary`) are not scanned; opaque data that is valid UTF-8 is scanned.
  Files without an extension (`Dockerfile`, `.bashrc`) are always scanned unless they
  start with executable magic; multi-dot names such as `.env.local` count their last
  suffix as the extension. A file with NUL bytes is matched as
  written and with the NUL bytes dropped; a finding from either counts once.
- New warn rule `coverage.nested_vcs`: a `.git` directory below the top of the target
  (not scanned, like the top-level one, but now visible). A `.git` file (worktrees,
  submodules) is scanned like any other file.
- New warn rule `coverage.surface_error`: one of frisk's scan surfaces failed on a file;
  the rest of the file and every other file are still scanned.
- `.html`, `.htm`, `.xml`, `.svg`, `.cfg`, `.ini` and `.conf` count as text files.
- Media files stay silent but are counted as skipped (`binary`); `.git` is recorded
  once as `vcs_dir`. A `.git` entry is now matched relative to the scanned target, so
  a target that is itself inside a `.git` directory (for example `.git/hooks`) is
  scanned instead of skipped entirely.
- Exit codes: `--fail-on warn` now fails on these warnings; the default
  `--fail-on block` is unchanged.

### Changed: finding paths are relative to the target you name (AUD-S8)
<!-- changes/AUD-S8.md, added in 72c5951 -->

`frisk` used to report every path relative to the target itself, so `frisk skills/`
printed `foo/SKILL.md`, two targets with the same layout produced identical paths, a
single-file target showed only its file name, and the GitHub Action's SARIF mapped to
repository files only when `targets` was `.`.

Paths now follow docs/adr/0001-finding-paths.md, in text, `--json` and `--sarif`
output and in `coverage.skipped`:

- a local directory: the target as given, normalised (no leading `./`, no `//`, `/.` or
  trailing `/`), joined
  with the in-target path, e.g. `frisk skills/` → `skills/foo/SKILL.md`; `.` is unchanged;
- a single file: exactly the argument;
- a git URL: relative to the clone (unchanged);
- `--mcp-config` servers: `name::path` (unchanged); `--text`: `<text>` (unchanged).

Paths are POSIX on every platform. The MCP server tools and `frisk lock`/`verify` are
unchanged.

### Changed: correct, deterministic SARIF; aligned text columns (F1.08)
<!-- changes/F1.08.md, added in 28ddb12 -->

- SARIF output is byte-identical across runs: rules sorted by id, results by
  (path, line, rule), keys sorted, no timestamps.
- `artifactLocation.uri` is POSIX and relative to the current directory for local
  targets (an absolute target is made relative, including `coverage.skipped` paths);
  git-URL results use `uriBaseId: "SRCROOT"`; `--text` and `--mcp-config` results carry
  a `logicalLocations` entry instead of a file location (docs/adr/0001-finding-paths.md).
- Each rule has `helpUri` (its anchor in docs/rules.md), its description from the rule
  table, and `properties.security-severity` (block 8.5, warn 5.0).
- Each result has `partialFingerprints["frisk/v1"]` = sha256 of rule id, path, the
  source line with whitespace collapsed and its occurrence index among identical
  triples, NUL-separated. The line number is not part of it, so inserting lines above
  a finding keeps its fingerprint.
- `report.to_sarif(result, version)`: `version` is now required (the stale `0.1.0`
  default is gone).
- Text output: the category column is as wide as the longest category
  (`tool-poisoning`), so every location starts in the same column.

### Fixed: edge cases found by the FR-E2 QA pass (FR-E2 t9)
<!-- changes/FR-E2-t9.md, added in 1de1e34 -->

- A leading UTF-8 byte-order mark is treated as encoding, not content: a file with a
  BOM scans exactly like the same file without it (before, a rule anchored at the
  start of the file missed its first line, and excerpts began with U+FEFF).
- A subdirectory that cannot be listed is no longer silently left out: it is recorded
  in `coverage.skipped` as `unreadable` and raises a `coverage.unreadable` warning.
- A target named twice (`frisk skill skill`, `frisk skill ./skill/`, or a relative and
  an absolute spelling of the same path), or a target inside another target directory
  (`frisk skill skill/SKILL.md`), is scanned once instead of doubling every finding,
  count and skipped entry. Paths are compared by real path; a target inside a `.git`
  directory or reached through a symlinked directory is kept, because the parent's scan
  skips those. The verdict line still lists the targets as typed.

Deferred to FR-E3a (markdown surface): unclosed ``` fences, ~~~ fences, and a longer
backtick fence that contains a shorter one are not yet scanned as code.

### Changed: rule precision (F1.07)
<!-- changes/F1.07.md, added in eb77a04 -->

Fewer false positives, and the narrowed rules still catch their attack forms.

- `exfil.secret_name` is case-sensitive: SCREAMING_CASE secret names (`GITHUB_TOKEN`)
  still warn; ordinary identifiers such as `access_token` no longer do.
- `destroy.rm_rf` matches a recursive, forced `rm` in any flag spelling (`-rf`, `-fr`,
  `-r -f`, `--recursive --force`; `-fr` and split flags were missed before) whose target
  is `/`, a top-level system directory (`/etc`, `/usr`, `/bin`, `/sbin`, `/var`, `/opt`,
  `/private`, `/System`, `/Library`, `/home`, `/Users`, `/root`), `~`, `$HOME`, `${HOME}`,
  a home credential directory (`.ssh`, `.aws`, `.gnupg`, `.config`, `.kube`, `.docker`),
  or a glob over them or a bare `*`, optionally quoted. `rm -rf /tmp/x`, `$TMPDIR/x`,
  `./build`, `node_modules` and other paths below those no longer block.
- `destroy.disk` matches `dd` writing to a `/dev` device (not `/dev/null`, `/dev/zero`,
  `/dev/stdout`, `/dev/stderr` or `/dev/fd/*`) and `mkfs` on a `/dev` device. `dd` to a
  regular file and `mkfs` on an image file no longer block.
- `inject.exfil_instr` accepts inflections (sends, sent, posted, uploading…) and one
  line break inside the sentence, but not a blank line. `examples/malicious-skill` now
  also reports it (one more warning; the verdict is still BLOCK).
- `rce.pipe_installer` also catches a shell named by path (`| /bin/sh`), reached through
  `env` or `sudo` with options (`| env sh`, `| sudo -E bash`), a download run by
  process substitution or `sh -c "$(…)"`, and a backslash-continued line before or after the pipe.
  It is reported at the download's line.

### Changed: hidden-Unicode coverage (F1.07)

- A zero-width joiner directly between two emoji (family emoji, heart on fire) no longer
  blocks; one anywhere else still does (`unicode.invisible`).
- Unicode tag characters (U+E0000 to U+E007F), which can carry invisible ASCII text, now
  block as `unicode.invisible`, except the tag sequence of the three recommended
  subdivision flags (England, Scotland, Wales: black flag, tag letters, cancel tag).
- New warn rule `unicode.hidden_format`: a run of two or more supplementary variation
  selectors (U+E0100 to U+E01EF), the invisible operators U+2061 to U+2064, the soft
  hyphen U+00AD, U+180E, and a byte-order mark anywhere but the start of the text. A
  single variation selector and a leading byte-order mark pass. These used to PASS.
- Findings report each class's first reported occurrence at its true line, as before.

### Changed: scripts and build commands are scanned as code (F1.04)
<!-- changes/F1.04.md, added in 43427c7 -->

More content gets the code rules (RCE, exfiltration, destructive), so payloads that used
to PASS now WARN or BLOCK.

- A file whose first line starts with `#!` is a script whatever its name or extension
  (an extensionless installer such as `setup` or a hook).
- New code extensions: `.tsx`, `.jsx`, `.mts`, `.cts`, `.ksh`, `.command`, `.vbs`,
  `.applescript`, `.psm1`.
- Build files: Makefile recipe lines (`Makefile`, `GNUmakefile`, `*.mk`; tab-indented
  lines and a recipe after `;` on a rule line), Dockerfile `RUN` instructions
  (`Dockerfile`, `Dockerfile.*`, `*.dockerfile`) and justfile recipe lines are scanned as
  shell, each command with its backslash-continued lines, at their file lines.
- `package.json`: each `scripts` value (for example `postinstall`) is scanned as shell at
  its line. The file is parsed as data only; a malformed `package.json` raises a
  `coverage.surface_error` warning and is still text-scanned.

### Changed: markdown code forms, HTML comments and credential-copy instructions (F1.06)
<!-- changes/F1.06.md, added in 21078e9 -->

- Markdown (`.md`, `.markdown`, `.mdc`) has its own scan surface. Code rules now also run
  on inline code spans, indented code blocks (4 spaces or a tab after a blank line,
  outside a list), `~~~` fences, fences of four or more backticks (a ```` fence holding a
  ``` example pairs correctly) and an unclosed fence, which runs to the end of the file.
  Payloads in these forms used to PASS. Inline code in an ordinary document (a README,
  `docs/`, any `.md`/`.markdown` that is not an agent-instruction file) is its own region
  (`md_inline_code`) and reports code rules at most as `warn`, so a README that mentions
  `eval()` or `pickle.loads` by name does not block; inline code in agent-instruction files
  and every code block keep the rule's severity. frisk's own `docs/` scans WARN, not BLOCK. Fenced blocks in other text files use the same
  fence finder, so `~~~`, longer and unclosed fences count there too. Backticks after
  text on a line (`Run: ```sh`) still open a fence when only a language tag follows.
- HTML comments, which renderers hide, are marked as their own text region
  (`md_html_comment`); an injection inside one blocks at its line, reported once.
- New block rule `inject.sensitive_path_instruction`, for agent-instruction files only
  (`SKILL.md`, `CLAUDE.md`, `CLAUDE.local.md`, `AGENTS.md`, `.cursorrules`, `*.mdc`, `*.md` in
  `agents/` or `commands/`, and `*.md` at any depth below `.claude/agents`, `commands`, `rules`,
  `skills` or `output-styles`): an instruction to copy, send, upload, read, cat, include, attach or
  print a credential location (the `.ssh` directory or a private key, cloud credential
  files, `.gnupg`, a private key, the keychain) in the same sentence. Public keys,
  `.ssh/config` and clauses that negate the verb ("never read …") do not match. The same sentence in a README is
  at most a warning. `examples/malicious-skill` now reports it on line 18 (4 blocking).
- A rule matching at the same file offset in two overlapping regions of a file is
  reported once.

### Fixed: the MCP config audit no longer prints URL credentials (AUD-S13)
<!-- changes/AUD-S13-redact.md, added in 7a56b8a -->

A skipped remote server's `→` line used to print its URL exactly as written in the
config, including a `user:password@` part, the query string and the fragment, which is
where access tokens usually sit. The audit now prints only the scheme, host and port,
plus `/…` when a path, parameters, query or fragment followed (`https://mcp.example.com/…`):
some providers put the access key in the path too (FR-E4 owner decision). A remote URL
with no scheme or host, with a port that is not a number, with anything but a host name or
address before the path (`;jsessionid=…`), or with an `@` after its host part is shown as
`<unparsable URL>`:
an unencoded `#`, `?` or `/` in a password makes the parser end the host part early, and
printing what it took for the host would show part of the password. A package given as a URL is shortened the same way. Env values and
headers are never read into the audit, so they cannot be printed. All audit output gets
a server's location from one function, `frisk.sources.display_ref`.

### Changed: MCP servers are classified the way they really launch (F1.09)
<!-- changes/F1.09.md, added in 4a90fac -->

`frisk --mcp-config` now finds each server's source the way the client starts it.

- `uv run` is local source, rooted at `--directory`/`--project` (before or after `run`),
  else at the project of the script it runs, else at the config's `cwd`. It used to be
  reported as an unscannable PyPI package named after the `--directory` value. `uv tool
  run` is a PyPI package, like `uvx`; any other `uv` command is `unknown`.
- Relative paths in `args`, and a relative `command` path, resolve against the server's
  `cwd` in the config, never against the directory frisk runs in. With no absolute `cwd`, a
  relative script makes the server `unknown` (a relative `cwd` is not used).
- For an interpreter (`python`, `node`, `bun`, `deno`, `ruby`, `bash`, `sh`, with any
  version suffix such as `python3.12`) the first script-like argument decides. A file with
  a code extension or a `#!` start is the entry point, and the scan root is the nearest
  directory holding `pyproject.toml`, `package.json` or `.git`, from the script's own
  directory up at most 3 levels and never `$HOME` or above it; with none, the script's
  directory (a script directly in `$HOME` is scanned alone). A named script that does not
  exist, or a relative one with no `cwd`, makes the server `unknown` instead of scanning a
  later argument such as a data directory. Only when no argument is a script does the
  first existing path count.
- Any other command's arguments are its data, not its source: a command given as a path
  (`/opt/srv/bin/server --db /data`) is scanned as that file, and a bare command name
  (`some-mcp --repository ~/repo`) is `unknown` instead of scanning the repository it
  serves.
- `$HOME`, or a directory above it, is never scanned as a server's source (`unknown`).
- `frisk lock`: entries that pinned a path keep verifying that path. A `uv` server pinned
  before this change as a package reference may report DRIFT once, because its reference is
  now the resolved directory rather than the `--directory` text; lock it again.

### Changed: a `.claude.json` target is audited as an MCP config, project servers included (F1.09)
<!-- changes/F1.09-claude-json.md, added in a10cad7 -->

- A target that is an MCP config file (`.claude.json`, `.mcp.json`, `mcp.json`,
  `claude_desktop_config.json`, or any `.json` file whose top level holds `mcpServers`) is
  audited exactly like `--mcp-config` instead of being text-scanned. `frisk ~/.claude.json`
  used to text-scan the file, which printed excerpts of the config itself (env values
  included) and audited none of its servers. A config named more than once (as a target and
  with `--mcp-config`, twice, or through a symlink or another spelling) is audited once,
  compared by resolved path; the verdict line still lists the names as typed. A config
  named as a target is audited even when another target directory holds it (that
  directory's scan still reads it as a plain file); the duplicate-target rule used to drop it.
- Every project's servers in a `.claude.json` (`projects.<path>.mcpServers`) are audited
  too, after the top-level ones. A project server is named `server (project)` with `$HOME`
  shown as `~`, for example `db (~/work/app)`, so the same server name in two projects, or
  in a project and at the top level, gives separate entries. A path under `$HOME` in a
  skipped server's `→` line is shown with `~` as well.
- A project server with no `cwd` (or a relative one) resolves its relative command and
  script paths against its project directory, the directory Claude Code starts it in (owner
  decision), so `node index.js` in a project is scanned instead of being `unknown`. The
  usual limits hold: the walk up to a project marker is at most 3 levels and never reaches
  `$HOME`, `$HOME` itself is never a root, a missing file stays unscanned, and top-level
  servers still need an absolute `cwd`.
- A config whose top level, `mcpServers` (and `servers`), `projects` or a project entry is
  present but not a JSON object now stops with exit code 2 and a message naming the config
  and the part, instead of a traceback or a silently partial audit. A config that cannot
  be read (no permission, or a directory) also stops with `frisk: <error>` and exit 2,
  never a traceback, whether it is named as a target or with `--mcp-config`; `frisk lock`
  and `frisk verify` do the same for their inputs. (Before this change an unreadable file
  named like a config was text-scanned with a `coverage.unreadable` warning, which under
  the default `--fail-on block` exited 0 with no server audited.)
- `frisk lock --mcp-config` pins each project server under its own key
  (`<config>::db (~/work/app)`). Top-level keys are unchanged, so lockfiles written before
  keep verifying; project servers are pinned once you lock again.

### Added: npx, uvx and pipx servers are scanned from the local package cache (F1.10)
<!-- changes/F1.10.md, added in 6aa8efb -->

`frisk --mcp-config` used to skip every package server ("fetch+scan not yet supported").
A server run by `npx`, `uvx`, `uv tool run` or `pipx run` (the command may be an absolute
path such as `/opt/homebrew/bin/uvx`) is now looked up in the local caches, offline:

- npx: `~/.npm/_npx/<hash>/node_modules/<pkg>`, only where that hash directory's
  `package.json` lists the package (a package npx was asked to run, not a dependency).
- uv: the tool environment `~/.local/share/uv/tools/<pkg>` and uv's cache
  `~/.cache/uv/archive-v0/*`; pipx: `~/.local/pipx/venvs/<pkg>`. The package is found by
  its `*.dist-info`, and its code is the one top-level package or module its `RECORD`
  lists.
- Roots can be overridden with `FRISK_NPX_CACHE` (the `_npx` directory), `FRISK_UV_TOOLS`,
  `FRISK_UV_CACHE` (uv's cache directory) and `FRISK_PIPX_VENVS`.

When exactly one version is found (a version pinned in the config, `pkg@1.2.3` or
`pkg==1.2.3`, must match exactly) the server's kind is `package-cached`: the package's own
code is scanned like local source, its detail names the version and the cache path (with
`~` for your home directory), and its declared dependencies are recorded, not scanned.
Otherwise it is skipped: `not in local cache; frisk does not download`, or, when several
versions are cached and none is pinned, `versions ... are cached; frisk cannot tell which
one runs`. A cache entry that cannot be read, is malformed, leads outside its cache (for
example a symlink), or is an editable install skips only that server
(`local cache entry unusable (...)`); the other servers are still audited. frisk never
downloads and never runs npm, npx, uv or pip; the lookup lives in `frisk.pkgcache`, which
imports no process or network module. Packages run by `npm`, `pnpm`, `bunx` or `pip` are
not looked up.

The package named by a runner is now read past its options: `npx -p PKG`, `uvx --from
PKG` (and options with values such as `--python 3.12`), `pipx run --spec PKG`.

`frisk lock` pins a cached package as its content plus its version (entry kind
`package-cached`); `frisk verify` finds it again through the live config, so a changed
version, a changed file, or a cache entry that disappeared (or is no longer the only
cached version) is DRIFT. A package entry locked before this change pinned the package
name from the config and keeps verifying, except for a `uvx`/`pipx` server whose old pin
had taken an option value or `run` as the package name, and an `npx` server with an option
that takes a value before the package (`--registry`, `--cache`, `--userconfig`, `--prefix`,
`-c`): such an entry reports DRIFT once with no changed file; lock it again.

### Changed: an MCP config audit is never PASS while a server went unscanned (F1.11)
<!-- changes/F1.11.md, added in 3d1748b -->

- Each server frisk does not scan (remote, a package not in the local cache, a source it
  could not resolve, or an invalid entry) raises the new warn rule `coverage.unscanned`
  (category `coverage`, OWASP LLM03:2025 Supply Chain) at `name::<location>`, with the
  message `MCP server not scanned (<kind>)`. An audit whose servers were all skipped used
  to print `frisk: clean` and PASS; it is now WARN. `--fail-on warn` fails on it; the
  default `--fail-on block` keeps exit code 0 for a WARN-only result.
- The text audit of each config ends with `N of M servers not scanned`, or
  `scanned M of M servers` when none was skipped.
- A cached package's line names the dependencies that were not scanned:
  `...; 2 dependencies not scanned: left-pad, zod`.
- `--json` gains `servers` when an MCP config was audited: one object per server with
  exactly `name`, `kind`, `status` (`scanned` or `skipped`), `reason` (the same text as the
  audit line) and `verdict` (`null` when skipped). A scan with no config has no `servers` key.
- A server entry that is not a JSON object, whose `command` is not a string (or, with no
  command, whose `url` or `serverUrl` is not; FR-E4 final review) or whose `args` is not a
  list, or that has neither a command nor a url, is
  reported as kind `invalid` (and warns) instead of stopping the audit with a traceback or
  being called `unknown`; the other servers are still audited.
- URL credentials, query strings and env values appear in none of the text, `--json`,
  `--sarif` and `-q` outputs.
- The text report and `frisk verify`'s text output show control characters (C0, DEL, C1)
  and the hidden Unicode frisk reports (bidi, zero-width, tag characters, ...) as escapes
  such as `\x1b` and `\u202e` wherever they come from a config, a package cache or a file
  name: server names, versions, dependency names, locations, finding paths and lock entry
  names. A crafted config can no longer erase a line or print a fake PASS. JSON and SARIF
  are unchanged: JSON already escapes them. Finding excerpts are escaped too (FR-E4 review).

### Changed: `frisk lock` pins an MCP config per server, never as a whole file (FR-E4, owner decision)
<!-- changes/FR-E4-lock.md, added in e9d9167 -->

- `frisk lock ~/.claude.json`, or any MCP config named as a target, used to pin the file's
  bytes, so every unrelated change Claude Code makes to the file was DRIFT. A config named
  as a target is now pinned exactly like `--mcp-config` (the same entries), and a config
  named twice is pinned once.
- Per config: one entry, `<config>` (kind `mcp-config`), lists its server names, so an
  added or removed server is DRIFT.
- Per server: `<config>::<name>` pins how it starts (command, args, cwd, type, the URL
  without credentials, query or fragment, and the names, not the values, of its env vars
  and headers) together with the code frisk scans for it: local source, or a cached package
  with its version. `frisk verify` shows a changed launch as `~ changed: how it starts
  (command, args, cwd, URL, env or header names)`, and `--json` adds `"launch": "changed"`.
  Rotating an env value, a header value or a URL token is not drift.
- Older lockfiles keep the checks they were written with. A config that an older frisk
  pinned as a whole file verifies while the file is unchanged; after that, `frisk verify`
  reports one error (exit 1), `MCP config pinned as a whole file by an older frisk: run
  frisk lock again to pin each server`, never a traceback.

### Fixed: holes found by the independent review of the MCP config audit (FR-E4)
<!-- changes/FR-E4-review.md, added in 5a34105 -->

- A config that holds both `mcpServers` and `servers` is audited whole. Claude Code runs
  `mcpServers` and VS Code runs `servers`; frisk used to read `servers` only when
  `mcpServers` was missing, so an empty `"mcpServers": {}` hid every VS Code server (main
  read `servers` when `mcpServers` was empty, so this was a BLOCK-to-PASS regression). A
  name found in both maps is listed twice, the second as `name (servers)`.
- A cached Python package that installs a script of its own into its environment's `bin/`
  (a wheel's `.data/scripts` file, which `uvx` and `pipx` run as the command) is skipped as
  `local cache entry unusable (...)` instead of passing on its package directory alone:
  frisk scans only the package, so such a server used to PASS with a pipe-to-shell
  installer in the script that actually runs. Wrappers generated for the package's own
  entry points (`entry_points.txt`) are accepted as before.
- `$HOME` and the directories above it are recognised with symlinks resolved. The guard
  compared paths as written, so a symlink to `$HOME` (one committed in a repo, or a `$HOME`
  that is itself a link) made the walk-up or a directory argument scan all of `$HOME`,
  printing excerpts of whatever matched there.
- The text report also escapes control characters in a finding's excerpt (the scanned line,
  which a malicious package writes: cursor moves, line erases, an OSC 52 clipboard write or
  'conceal' could hide its own BLOCK line), in the target names on the verdict and `-q` lines
  and in error messages (a project key). A lone surrogate in a server name (valid JSON) is
  shown as `\ud800`; it used to stop the text and `--sarif` reports with a traceback and
  `frisk lock` with exit 2.
- A skipped server whose `command` holds a whole command line (`npx -y pkg --api-key …`,
  `docker run -e TOKEN=… img`) is shown by its program alone (`npx …`); its arguments,
  and any token among them, used to be printed in every output format.
- `frisk verify` reads each MCP config once, not once per pinned server: verifying 2,000
  servers took 25 s (quadratic; main was quadratic too, about 10 times cheaper per read)
  and now takes 0.1 s. Naming many config files as targets is linear too.

### Changed: owner decisions on the FR-E4 review's open items
<!-- changes/FR-E4-owner.md, added in f55d74c -->

- **A command beside a url is scanned (N1).** An entry with both a `command` and a `url`
  (or `serverUrl`), whatever its `type`, used to be classified as remote, so a decoy URL
  kept the command's script from being read (a pipe-to-shell installer passed as WARN, or
  PASS before FR-E4). The command is now classified and scanned like any other server, so
  it can BLOCK, and the entry also raises a `coverage.unscanned` warning that it names a
  remote URL, which frisk does not scan. The text line and the JSON `reason` name the URL
  (redacted like every URL). An entry with only a `url` is still a remote server.
- **Code-loading env values are pinned (N2).** `frisk lock` pinned only the names of a
  server's env variables, so changing `NODE_OPTIONS` from empty to
  `--require /tmp/evil.js` was not drift. The values of these variables are now pinned, as
  sha256 hashes in the lockfile: `NODE_OPTIONS`, `NODE_PATH`, `PYTHONPATH`, `PYTHONSTARTUP`,
  `PYTHONHOME`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_INSERT_LIBRARIES`, `DYLD_LIBRARY_PATH`,
  `DYLD_FRAMEWORK_PATH` and any other `DYLD_*`, `PERL5OPT`, `PERL5LIB`, `RUBYOPT`, `RUBYLIB`,
  `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`, `BASH_ENV` and `ENV`. A changed value is DRIFT;
  `frisk verify` prints `~ NODE_OPTIONS changed` (JSON: `"env": ["NODE_OPTIONS"]`) and never
  the value. Every other env value stays unpinned, so rotating a secret is still not drift.
  A lock entry written before this change for a server that sets one of these variables
  reports DRIFT once with that line: lock again. Other entries verify as before.
- **URLs are shown by their host only (N3).** Every URL frisk prints from a config, in the
  text report, `--json`, `--sarif`, `-q`, `frisk verify` and debug lines, is now
  `scheme://host[:port]`, plus `/…` when anything followed the host
  (`https://mcp.example.com/…`). The path used to be shown, and some hosted MCP providers put
  the access key in it (`/mcp/<key>/sse`), as do session parameters (`;jsessionid=…`). A URL
  whose host part holds anything but a host name or address is `<unparsable URL>`, as are
  the DEFECT-1 shapes. `frisk lock` still pins the path (without credentials, query or
  fragment), so a changed endpoint is still drift and existing lockfiles verify as before.
- **A console-script wrapper is not passed on itself (N4).** A `command` that is a small
  generated wrapper (pip, pipx and uv write a few lines that import a package's entry point
  and call it in `sys.exit(...)`; `uv tool install` links it into `~/.local/bin`), a shell
  shim that execs node (pnpm, cmd-shim), or a file inside a node package (where an npm bin
  link points) used to be scanned as that one file and PASS, while the package that really
  runs was never read. Such a server is now kind `wrapper`: not scanned, a
  `coverage.unscanned` warning naming the package (`console-script wrapper or bin shim for
  the Python package 'acme_mcp', which frisk does not scan`), so WARN, never PASS. The
  wrapper file itself is still read, so a payload hidden in it BLOCKs. Larger scripts, and
  scripts that call a function they define themselves, are scanned as before.
- **A config with no servers warns (N5).** A config in which frisk found no servers printed
  `(no servers found in config)`, `frisk: clean` and PASS, also when it was a format frisk
  does not read. New warn rule `coverage.no_servers`: such a config is WARN with `no MCP
  servers found in <file> (frisk reads 'mcpServers' and 'servers', at the top level and in
  each 'projects' entry)`, as a target and with `--mcp-config`, in every output format
  (`--fail-on warn` exits 1). No config format was added: VS Code's `settings.json`
  (`mcp.servers`), Zed's `context_servers` and a misspelt `mcpservers` are still not read,
  and now say so. The text report also escapes a finding's description, which can now
  carry a file name.
- **A git URL target never prints or stores its credentials.** A git URL given as a scan
  target used to be echoed as typed in the verdict line, `-q`, `--json` (`target`), error
  messages, `frisk-mcp` results and the lockfile, `user:token@` included. It is now shown
  and pinned without userinfo, query or fragment; scheme, host, port and path stay, so two
  repositories stay apart in `frisk verify`. An ssh username such as `git@` is kept, a
  password beside it is not. The clone still uses the URL as given. A failed clone of a URL
  that carried credentials does not show git's own message, since it could echo the token.
  `frisk lock` stores the clean URL and `frisk verify` re-clones it: for a private
  repository, git's credential helper (or an ssh key) supplies the access. A URL whose host
  part cannot be told from a password is not pinned (exit 2). A lockfile written before
  this change with a token in a git URL still verifies (it clones the URL it stored) and
  never prints the token; the next `frisk lock` rewrites it without the token. **If a
  lockfile holding a token was ever committed, rotate that token.**

### Fixed: holes found by the final review of the MCP config audit (FR-E4)
<!-- changes/FR-E4-final-review.md, added in 29a4d89 -->

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
- `frisk lock` pins a console-script wrapper's own file again. Since wrappers became kind
  `wrapper` (not scanned), their bytes were left out of the lock, so a wrapper changed after
  `frisk lock` verified with no drift, where main (and the branch before) reported DRIFT. The
  package the wrapper runs is still neither scanned nor pinned.

### Fixed: follow-ups from the FR-E4 reviews (FR-FX1)
<!-- changes/FR-FX1.md, added in 200ff7a -->

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
- Every value `frisk lock` hashes passes through frisk's redaction first: each code-loading
  env value and every part of how a server starts (command, arguments, cwd, type, URL). The
  redaction is the one the debug lines use, which now also covers a URL's `user:password@`
  and a `Basic` credential beside `key=`/`token:`/`secret`/`password`/`authorization`/
  `cookie` values, `Bearer` credentials and `sk-`/`gh*_`/`github_pat_` tokens. A secret in
  an argument (`--api-key=…`), in git configuration (`http.extraHeader` set to
  `Authorization: Basic …`, an inline credential helper that echoes `password=…`) or in
  `JAVA_TOOL_OPTIONS` (`-Dpassword=…`, `-Dapi.key=…`) is pinned as a fixed marker, never
  stored, not even as a hash: rotating it is not drift, a changed option name, host or
  command still is. A server URL frisk cannot split is pinned as `<unparsable URL>` and its
  length class instead of whole. Values with no secret hash exactly as before, so their lock
  entries are unchanged; an entry whose values held a secret, or such a URL, reports DRIFT
  once (`~ changed: how it starts`, or the variable's name): lock again. The redaction goes
  by those patterns: a bare token passed as an argument of its own is still pinned as
  written, and a value that merely follows such a name (`--keyfile=…`) is pinned without it.

### Fixed: holes found by the review of the FR-E4 follow-ups (FR-FX1)
<!-- changes/FR-FX1-review.md, added in e7dd3d5 -->

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

### Fixed: holes found by the last-fix review of the FR-FX1 review's on-top
<!-- changes/FR-FX1-lastfix.md, added in 747656a -->

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
- A changed version pin is drift again when the package's name holds a key, token,
  secret, password, authorization or cookie name. Since FR-FX1 10 a value after such a name
  and `=` is redacted before it is hashed, and the name is found anywhere in a word, so
  `mcp-keycloak==1.0.0`, `tiktoken==0.7.0` or `keyring==24.0` (in `uvx --from`, `uv run
  --with`, `pipx run --spec`, a `pip install` in `sh -c`) was pinned without its version,
  and changing the version, which decides what code runs, was not drift where the package
  was not in the local cache (as in CI). A name followed by `==` is no longer read as the
  start of a secret; `--api-key=…`, base64 padding after it and `PASSWORD:=…` are
  redacted as before. A server holding such a pin, locked before, reports DRIFT once: lock
  again.

### Fixed: the proxy fails closed (FR-E5 t1, security)
<!-- changes/FR-E5-t1.md, added in 100853d -->

`frisk proxy` used to forward a message exactly as the server sent it whenever inspecting
it raised. One tool entry that was not an object (a string, `null`), or a tool whose
description was not a string, made the inspection of the whole `tools/list` result fail,
so every tool in it, a poisoned one included, reached the client. A JSON-RPC batch (an
array) was never inspected at all, and a server line that was not JSON was passed through
unchanged.

Now:

- each tool is judged on its own: an entry that is not an object with a string `name` and
  a string `description` (a missing or null description counts as empty, as MCP makes it
  optional), or whose inspection raises, is dropped and logged, and the other tools are
  still judged;
- a tool-result content item that is not an object, or a text item whose `text` is not a
  string, is dropped and logged;
- if inspecting a message's `tools` or `content` fails (for example, one of them is not a
  list), the client gets `{"jsonrpc": "2.0", "id": <its id>, "error": {"code": -32603,
  "message": "frisk: inspection failed"}}` instead of the message;
- a batch is inspected message by message (an element that is not an object is dropped);
- a server line that is not JSON, or JSON nested too deep to read, is dropped and logged
  with its length only.

Messages that carry no tools or content, notifications included, are relayed unchanged.

### Changed: every rule scans in linear time, checked on 1 MiB of adversarial text (FR-E5 t4)
<!-- changes/FR-E5-t4.md, added in 3731121 -->

Some rules rescanned the same text from every start they found, so a file made of many
starts took far too long: `rce.shell_true` and `rce.eval_b64` were quadratic (1.4 s and
2.4 s on 64 KiB of `subprocess.run(` or `eval(` repeated; 1 MiB would take minutes), and
`destroy.rm_rf`, `exfil.secret_env_read`, `inject.exfil_instr` and `inject.read_then_send`
took 0.4 to 3 s per MiB on Python 3.9. Each now takes at most about 0.4 s per MiB of its
worst input, and `tests/test_perf.py` holds every rule and every scan-surface regex to 1 s
of CPU time on 1 MiB of each of its adversarial inputs (and the scan loops to linear growth).

What a rule finds is unchanged, except:

- `rce.shell_true` and `rce.eval_b64` look for `shell=True` or a base64 decode within 400
  characters of the call (it was any distance inside the parentheses).
- `destroy.rm_rf` looks for the flags and the target in the next 256 words of the command
  (it was 32, so more padded commands are caught), and reports one finding per command, at
  its first `rm` word: a command such as `rm a rm b rm -rf /` was reported at each `rm`
  whose 32 words held flags and target.
- `inject.exfil_instr` allows 41 characters between `to` and an `http://` URL (40 for
  `https://`, as before).
- Where a rule's window held another start of the same rule (another `subprocess` call,
  `eval(`, `$`, read/cat/open, or send/post/upload verb), the finding is now reported at
  that later start, which matches the same text: the same line, unless the window crossed
  a line break.

### Fixed: frisk-mcp answers malformed requests instead of crashing (FR-E5 t3)
<!-- changes/FR-E5-t3.md, added in 0f97b1d -->

`frisk-mcp` used to end with a traceback on a request that was valid JSON but not an object
(`[1]`), a non-string `method`, or `tools/call` with list `params`; under a UTF-8 locale one
byte that was not UTF-8 ended it too. A line that was not JSON got no reply at all.

Now every request gets a reply and the server keeps serving:

- `-32700` "parse error" (id `null`) for a line that is not JSON, not UTF-8, or nested too
  deep to read;
- `-32600` "invalid request: ..." for a request that is not an object, whose `method` is
  not a string, or whose `params` or `tools/call` `arguments` is not an object;
- `-32602` "unknown tool: ..." for a `tools/call` naming no frisk tool (it was an `isError`
  result);
- `-32603` "internal error (...)" when handling a request fails inside frisk; a tool that
  cannot do its job (a missing path, a failed clone, a missing argument) still answers with
  an `isError` result.

`ping` answers `{}` (it was "method not found"). `initialize` negotiates the protocol
version: the client's version when it is `2024-11-05`, `2025-03-26` or `2025-06-18`, else
`2025-06-18` (it was always `2024-11-05`).

### Fixed: frisk verify tells drift from entries it could not verify; git never prompts (FR-E5 t6)
<!-- changes/FR-E5-t6.md, added in 2fad48d -->

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

### Changed: scans are bounded, and a bound that is hit is a visible warning (FR-E5 t5)
<!-- changes/FR-E5-t5.md, added in a50f43d -->

- A file larger than `--max-file-bytes` (new flag; default 2 MiB, 2097152 bytes) is no
  longer read: it is listed in coverage with reason `too_large` and raises the new
  block-severity finding `coverage.too_large`, so the scan fails under the default
  `--fail-on block` (and the Action's default): a script padded past the limit must not
  pass a gate that would block it whole. Raise `--max-file-bytes` to scan such a file, or
  leave it out of the target. frisk used to read every file whole, whatever its size.
- A directory target is walked one directory at a time in name order (it used to be listed
  whole first) and the walk stops after 20,000 files with a `coverage.unscanned` warning
  (reason `file_cap`) at the target. The engine's `ScanLimits` can also stop it at a byte
  total (`byte_cap`) or a time limit (`deadline`); frisk-mcp uses those (FR-E5 t7).
- Text over the limit (`--text`, frisk-mcp `scan_text`, the proxy's tool descriptions and
  results; 2 MiB characters, or `--max-file-bytes` for `--text`): the rules run on its first
  and last halves of the limit (line numbers count from the start of the whole text), the
  hidden-Unicode check on all of it, and a new warning, `coverage.truncated`, says so. This
  replaces the ask's "scan the first cap bytes": a payload placed at the end is still found.
- `coverage.unscanned` now also covers trees left unscanned by a limit; its description in
  SARIF says so.

### Fixed: the proxy survives bad bytes and never leaves its server running (FR-E5 t2)
<!-- changes/FR-E5-t2.md, added in 3d75f9a -->

- One byte from the server that was not valid UTF-8 ended `frisk proxy` with a traceback
  (under a UTF-8 locale). The relay now decodes without failing; the line holding such
  bytes is dropped and logged, and the next messages are relayed. Client input is relayed
  byte for byte.
- The real server is stopped (SIGTERM, then SIGKILL after 5 s) and reaped on every way the
  proxy ends. A client that stopped reading ended the proxy with a `BrokenPipeError`
  traceback and left the server running; it now logs `client gone`. SIGTERM or SIGINT to
  the proxy stops the server too. When the client closes the proxy's input, the server gets
  5 s to exit before it is stopped. The exit code is the server's status (128 + the signal
  number when a signal ended it, which `frisk proxy` used to pass on as a negative number).
- A tool result over frisk's text limit (2 MiB characters) is delivered, prefixed
  `[frisk: partially scanned — ...]`, scanned by engine.scan_text's head-and-tail policy.
  A tool over that limit is dropped instead: a payload in its unscanned middle would reach
  the model (main scanned it whole and dropped a poisoned one).
- `frisk proxy` exits 2 with one line when the server command cannot be started for any
  reason (it caught only a missing command: a file without the execute bit was a traceback)
  or when `--log` cannot be opened (also a traceback); the log file is closed on every path.

### Added: frisk-mcp scope limits (FR-E5 t7)
<!-- changes/FR-E5-t7.md, added in f6d044c -->

`scan_artifact('/')` used to scan the whole disk synchronously, holding frisk-mcp for hours.

- `scan_artifact` and `vet_mcp_server` now stop after 20,000 files, 200 MiB read or 30 s
  (and skip files over 2 MiB), returning what they found. Any incomplete result (a limit, a
  skipped file, text over the limit) adds `"degraded": true` and `"coverage":
  {"files_scanned": N, "skipped": {reason: count}}` to the JSON.
- New `FRISK_MCP_ROOTS` (an os.pathsep-separated list): a local path outside these
  directories is refused; symlinks and `..` are resolved first.
- New `FRISK_MCP_NO_NETWORK=1`: git URLs are refused before git runs.
- `/`, `$HOME` itself and `/System` are refused unless named in `FRISK_MCP_ROOTS`.
- A refusal is an `isError` result with a one-line reason. Results still never include
  excerpts.

### H1.3: a scan never reads outside its root (FR-E6)
<!-- changes/H1.3.md, added in 05af508 -->

- New rule `fs.symlink_escape` (category exfil, warn): a symlink in the scanned tree, or a
  single-file target that is a symlink, whose resolved target lies outside the scan root is
  never opened. The finding names the link and its target as the link spells it, with no
  excerpt, and the link is listed in coverage.skipped with reason `symlink_escape`. It
  blocks when the target is a credential location under `$HOME` (`.ssh`, `.aws`, `.gnupg`,
  `.config/gcloud`, `.azure`, `.kube`, `.docker/config.json`, `.netrc`), inside one, or a
  directory holding one, also when the link spells it another way (another case on a
  case-insensitive file system, a macOS `/System/Volumes/Data` path). Before this, such a link was read and its matching line printed in
  excerpts (text, JSON, SARIF).
- A symlink to a file inside the root is scanned once, at the target's path (it was read
  at the link's path before, so a linked file could be reported twice).
- New coverage.skipped reasons: `loop` (a symlink that loops) and `special` (a FIFO,
  socket or device, never opened; detail `fifo`, `socket` or `device`).
- `src/frisk/walk.py` is the one directory walker (os.walk with followlinks=False and
  os.lstat on every file entry).
- An MCP config audit reads a server's code where its configured path leads (the config
  names what runs), so a symlinked executable or wrapper is audited as before.
- frisk lock pins a symlink (to a file or a directory) by its target as os.readlink spells
  it, never by the target's bytes, through the same walker: content outside the tree is
  never read, and retargeting a link is drift. A lockfile of a tree holding symlinks gets a
  new digest: run frisk lock again. Trees without symlinks keep their digest.
- A lock target that is itself a symlink is pinned as it is scanned: a symlinked directory
  by its content, a file link by its target's bytes when the target lies in the link's
  own directory (else by where it points).

### H1.4: git clone of untrusted URLs with every escape hatch closed (FR-E6)
<!-- changes/H1.4.md, added in cf76d69 -->

- git now runs as `git -c protocol.allow=never -c protocol.https.allow=always
  -c protocol.ssh.allow=always -c core.hooksPath=/dev/null -c core.symlinks=false
  -c core.fsmonitor=false clone --depth 1 --no-recurse-submodules --quiet -- <url> <tmp>`,
  with `GIT_TERMINAL_PROMPT=0`, `GIT_LFS_SKIP_SMUDGE=1`, `GIT_ASKPASS=/bin/false`,
  `GIT_CONFIG_NOSYSTEM=1` and `GIT_SSH_COMMAND='ssh -o BatchMode=yes'` (replacing one set in
  the environment). So an `http://` git URL no longer clones: use `https://`.
- A git target holding whitespace or a control character inside it, or whose host starts
  with `-`, is refused before git runs (exit code 2).
- `file://` targets are never cloned. A test-only seam (a module flag set by a test AND
  `FRISK_TEST_ALLOW_FILE_URL=1`) allows them, and only then does git get
  `-c protocol.file.allow=always`.

### H1.5: the GitHub Action without script injection; one scan with --sarif-out (FR-E6)
<!-- changes/H1.5.md, added in 6d70392 -->

- New flag `--sarif-out FILE`: writes SARIF 2.1.0 to FILE from the same scan, while the
  report is printed as usual and the `--fail-on` exit code is kept; an unwritable FILE exits 2.
- action.yml no longer puts `${{ inputs.targets }}` or `${{ inputs.fail-on }}` into its
  scripts (GitHub's documented script-injection pattern: a targets value such as
  `.;<command>` ran the command). Inputs arrive through env (`FRISK_TARGETS`,
  `FRISK_FAIL_ON`), targets are read into a bash array, and each word is a literal path
  after `--`.
- frisk is installed into `$RUNNER_TEMP/frisk-venv`, not the runner's system Python.
- One scan instead of two. SARIF is always written to `$RUNNER_TEMP/frisk.sarif` (it was
  `frisk.sarif` in the workspace); the `sarif` input gates only the upload, which needs
  `permissions: security-events: write`.
- A multi-line `targets` value is scanned whole: every line, split on whitespace.

### F3.06: secret-like values are masked in scan excerpts (FR-E6)
<!-- changes/F3.06.md, added in 5c09948 -->

- Every finding excerpt (text, `--json`, `--sarif`, `--sarif-out`, `--text`; SARIF may be
  uploaded to GitHub) masks secret-like values as `****(len=N)`: a value after a secret's
  name and `=`, `:` or `=>` (the name stays), a Bearer/Basic credential, a URL's
  userinfo, sk-/gh*_/github_pat_ tokens, AKIA/ASIA access-key ids, PEM private-key blocks,
  and high-entropy runs of 32+ base64 or hex characters (letters and digits mixed). A
  secret the excerpt window cuts is masked whole. Excerpts without such values are
  unchanged (examples/ output is byte-identical).
- One redactor, `src/frisk/redact.py`, built on the secret pattern frisk's debug lines and
  lockfile already use (`debug.secrets_pattern`), so the two cannot drift apart; the debug
  and lockfile patterns themselves are unchanged.

### F3.01: the proxy inspects every server-to-client shape (FR-E6)
<!-- changes/F3.01.md, added in 2d3639f -->

- `frisk proxy` now inspects, by message shape: a tool's `title`, `annotations` and
  `outputSchema` (with name, description and input schema; a block in any drops the tool;
  every schema string is scanned as text, newlines kept); `prompts/list`, `resources/list`
  and `resources/templates/list` entries (a block drops the entry); embedded-resource text
  in content; `structuredContent` (a warning item is put first in `content`, since
  structuredContent must match the output schema); `prompts/get` messages; `resources/read`
  contents; and `initialize` `instructions`. All of these were relayed uninspected.
- Server-to-client requests `sampling/createMessage` (messages and system prompt) and
  `elicitation/create` (message and requested schema) with a block-level finding, too long
  to scan whole, or unreadable, are never forwarded: the server gets a JSON-RPC error for
  the request's id, code `-32001`, `frisk: request refused (possible prompt injection)`.
- A tool whose `title` is not a string is dropped. Wrong types in the new shapes fail
  closed (an inspection-failed error to the client, or the item dropped), never crash the
  relay.
- A `sampling/createMessage` or `elicitation/create` message with no `id` is dropped.
- An error answer whose `message` or `data` carries a block-level finding (clients show it
  to the model as the tool's answer) gets the warning first in its message, and its `data`
  is removed. A content item that is neither text nor an embedded resource (a
  `resource_link`, an item of no known type) is dropped when a string in it, binary
  `data`/`blob` aside, has a block-level finding.

### F3.02: persistent proxy pins over the whole tool definition (FR-E6)
<!-- changes/F3.02.md, added in 1d1d2cd -->

- `frisk proxy` pins each tool by sha256 of the canonical JSON of its name, title,
  description, inputSchema and annotations (it hashed the description only, so a
  schema-only swap went unflagged), and keeps the pins across runs (they lived in memory,
  so a rug pull between client restarts went unflagged, though the docs claimed otherwise).
- New flags: `--pins FILE` (default
  `${XDG_STATE_HOME:-~/.local/state}/frisk/pins/<sha256 of the server command>.json`),
  `--no-pins` (memory only, writes nothing), `--on-change flag|drop` (default flag; drop
  drops a changed tool and keeps its old pin).
- The pins file maps tool names to hashes only; it is written atomically with mode 0600 in
  a 0700 directory, only while the proxy runs. An unreadable or corrupt file is logged and
  treated as a first run; a failed write is logged once (`pins not persisted`) and the
  relay goes on with pins in memory.
- The flag note on a changed tool now reads `definition changed since it was pinned
  (possible rug pull)`.

### F3.07: the lockfile catches real upstream changes (FR-E6)
<!-- changes/F3.07.md, added in 3f2d107 -->

- The lockfile stays version 1. `frisk verify` (and `read_lock`) now refuses a lockfile
  whose `version` is missing or anything but 1, with exit code 2 and one line.
- A local target or config inside the lockfile's directory is also stored relative to it
  (a new `relative` field in the entry's `recompute`), and `frisk verify` reads it from the
  lockfile's directory, so a lock made in one directory verifies from another and in a
  copy or checkout of the tree. Entries without the field (older locks, paths outside the
  lockfile's directory) are read as before; re-lock to add it. Digests are unchanged.
- `frisk lock` prints `unpinned: upstream changes cannot be detected; pin <pkg>@x.y.z` to
  stderr for each npx/uvx/pipx server whose registry package has no exact version.
- Already in place since FR-E4 and now covered by tests/test_pin_spec.py: a server is
  pinned by command, every arg, cwd, the URL without query or credentials, and env and
  header names (never values), so an added flag or a changed URL path is DRIFT and a
  rotated env value is not.
- `frisk lock` also prints `code not pinned, only how it starts (<reason>)` for each package
  server it found no single cached copy of (FR-E4's cache lookup, reused); it is a note,
  not an error, and the lock is written. A cached package is pinned by its content through
  the shared walker, so a symlink in it is pinned by where it points.

### Changed: `.json` files are scanned by what their strings mean (F1.05, FR-E3b item 4)
<!-- changes/F1.05.md, added in 3574a2c -->

- A `.json` file is parsed as data (never run) and each string is read as the value it
  decodes to. The value of a `command`, `run`, `script`, `shell` or `exec` key (an array of
  strings under one is joined with spaces), an `args` array joined after its object's
  `command` (wherever the two sit), and any other string value holding a shell pipeline get
  the code rules. So a `hooks/hooks.json` hook or an `.mcp.json` server that pipes a
  download into a shell, or runs one through `bash -c`, now BLOCKs (`rce.pipe_installer`);
  both used to PASS. A finding is reported at the line of its string; for an `args` join,
  at the line of its `command`.
- A string written with backslash escapes (`ignore ...`, `​`) is also text-scanned
  and Unicode-checked as it decodes, so an escaped injection phrase or zero-width space is
  found (they used to PASS). A string written plainly is reported once, as before.
- A `.json` file that does not parse (a trailing comma, comments, nesting too deep for the
  parser) is still text-scanned as before, and now also raises a `coverage.surface_error`
  warning with a `coverage.skipped` entry `surface_error`, detail
  `json_values: JSONDecodeError` (or `RecursionError`): its strings could not be decoded.
  Other files in the scan are unaffected.
- No JSON reader converts a huge integer literal any more (Python 3.9 takes quadratic time
  on one; 3.11+ refuses one of over 4300 digits). The `.json` and `package.json` surfaces
  read the digits as written, so a command beside one is still scanned; an MCP config or a
  proxied server line holding one is refused as not JSON at once, on every Python version,
  as 3.11+ already did.

### Changed: the proxy judges tool descriptions and tool results by what they are (F2.08, AUD-S17; FR-E3b item 5)
<!-- changes/F2.08.md, added in ff6d147 -->

- `frisk proxy` used to run every code and text rule on everything. Now each rule names the
  contexts it runs in, and `engine.scan_text(text, label, context)` takes one:
  - `default` — every code and text rule, as before: `--text` and frisk-mcp's `scan_text`
    are unchanged.
  - `tool_description` — tool definitions, prompt and resource listing entries, the
    server's `instructions` and elicitation requests: the text rules, hidden Unicode, `rce.pipe_installer`,
    `exfil.keychain_read`, `destroy.rm_rf`, `destroy.disk`, `destroy.forkbomb`,
    `inject.sensitive_path_instruction` (block), the new `exfil.secret_files_prose` (block): a
    private key or credential file named however it is asked for, and the new
    `exfil.secret_paths_prose` (warn): a credential directory or config file named in prose.
  - `tool_result` — everything else the model reads (tool results and structured content,
    `prompts/get` messages, `resources/read` contents, error answers, sampling requests):
    the injection and tool-poisoning text rules, `inject.sensitive_path_instruction`,
    `rce.pipe_installer`, `exfil.keychain_read`, `destroy.rm_rf`, `destroy.disk`,
    `destroy.forkbomb` and hidden Unicode: a result telling the agent to pipe a download
    into a shell or wipe a directory is still annotated, and such a sampling request refused.
- So a tool described as showing the hosts in `~/.ssh/config` is kept, annotated with the
  warning (it used to be dropped by `exfil.secret_paths`), while a description telling the
  model to read the private key in that directory and pass it on is still dropped
  (`inject.sensitive_path_instruction`), and a tool result or sampling request holding
  Python code that calls `eval` is no longer marked as prompt injection or refused, while an
  "ignore previous instructions" phrase in one still is. Every shape the proxy inspected is
  still inspected, and it still fails closed.
- Log lines name the worst finding's rule id (a block-level one even when a warning sorts
  first) and the number of findings, e.g. `BLOCKED tool 'x': inject.ignore_prev (2
  findings)`; they used to give the first finding's description. They never hold the text of
  a description, result or request: a dropped content item's `type` is no longer logged. A
  flagged tool's description prefix names the worst finding's description and rule id.

### Changed: `frisk --help` names the proxy subcommand (FR-E7 t1)
<!-- changes/FR-E7-t1.md, added in 5adbf4a -->

The scan help's description now ends "Subcommands: lock, verify, proxy." (it listed only
lock and verify). Colour is now decided each time text is coloured, from whether stdout is a
terminal and whether `NO_COLOR` is set at that moment, not once when frisk is imported; the
output of a run is unchanged.

<!-- /entries -->

## 0.2.0 — 2026-07-02 — not released to PyPI

Tagged `v0.2.0` (and the floating `v0`) at commit 0e93c3c, never uploaded to PyPI: its
proxy fails open (a message whose inspection raised was forwarded unchanged; fixed in 0.3.0,
FR-E5 t1).

- Added `frisk proxy`, a stdlib-only stdio JSON-RPC proxy between an MCP client and server:
  it re-checks tool descriptions on every load, drops tools with block-level findings, flags
  a description that changed since it was first seen (rug pull), and warns on injection in
  tool results.

## 0.1.0 — 2026-06-24 — on PyPI

The first release (tag `v0.1.0`).

- A static, zero-execution scanner for MCP servers, Claude Code skills and plugins, and
  Cursor rules, detecting remote code execution, secret exfiltration, destructive
  operations, prompt injection, tool poisoning and hidden-Unicode obfuscation, with OWASP
  LLM Top 10 mapping.
- Text, `--json` and `--sarif` output; `frisk lock` and `frisk verify` for rug-pull
  detection; a GitHub Action; `frisk-mcp`, an MCP server so an agent can vet a tool before
  installing it.
- A PyPI trusted-publishing workflow and the `examples/continuous-verify.yml` monitoring
  template.
