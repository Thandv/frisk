# frisk rule reference

One section per rule id. Each anchor equals the id exactly, so `docs/rules.md#<rule-id>` links
(SARIF `helpUri`) resolve. Payloads are described in words; this page contains none.
`tests/test_rules_doc.py` fails when a rule in `src/frisk/rules.py` has no section here,
or when a section's severity or category disagrees with the code.

Severity: **block** fails a scan by default; **warn** fails only with `--fail-on warn`.

## Code rules

Run on script files (`.py`, `.sh`, `.js`, `.tsx` and the other code extensions, or any file whose first line is a `#!` shebang), on fenced code blocks (` ``` ` or `~~~`, any length; an unclosed fence runs to the end of the file) in every other text file, on indented code blocks and inline code spans in markdown (`.md`, `.markdown`, `.mdc`), and on the shell commands in build files: Makefile recipe lines (`Makefile`, `GNUmakefile`, `*.mk`), Dockerfile `RUN` instructions (`Dockerfile`, `Dockerfile.*`, `*.dockerfile`), justfile recipe lines and the `scripts` values of `package.json`. Backslash-continued lines belong to their command.

Inline code spans in an ordinary markdown document (a README, `docs/`, any `.md` or `.markdown` that is not an agent-instruction file) report a code rule at most as `warn`: a document that mentions a risky call by name is not running it. In agent-instruction files (`SKILL.md`, `CLAUDE.md`, `AGENTS.md`, `*.md` in `agents/` or `commands/`, `.cursorrules`, `*.mdc`) and in fenced or indented code blocks everywhere, code rules keep the severity listed below. Text rules keep their severity in every form.

<a id="rce.pipe_installer"></a>
### rce.pipe_installer

- Severity: `block` · Category: `rce` · OWASP LLM Top 10 (2025): LLM03:2025 Supply Chain
- Matches: A `curl` or `wget` command whose output is piped into a shell or a Python interpreter on the same line or across backslash-continued lines (before or after the `|`), where the shell may be named by a path (`/bin/sh`) or reached through `sudo` or `env` with options; or a `curl`/`wget` download run by a shell through process substitution (`bash <(…)`) or `sh -c "$(…)"`.
- Likely false positive: Install instructions in a README that tell a human to run a vendor's official installer.
- On a hit: Do not run it. Download the script, read it, and pin it by hash; prefer a package manager.

<a id="rce.eval_b64"></a>
### rce.eval_b64

- Severity: `block` · Category: `rce` · OWASP LLM Top 10 (2025): LLM03:2025 Supply Chain
- Matches: A call to `eval` or `exec` whose arguments decode base64 inside the same parentheses.
- Likely false positive: Rare. Test code that exercises a decoder through `eval`.
- On a hit: Treat as hostile: decode the payload offline (never execute it) and see what it does.

<a id="rce.python_exec"></a>
### rce.python_exec

- Severity: `block` · Category: `rce` · OWASP LLM Top 10 (2025): LLM03:2025 Supply Chain
- Matches: A bare `exec(` or `eval(` call (not a method such as `re.exec`), or `os.system(` / `os.popen(`.
- Likely false positive: Build scripts that call `os.system` with a fixed command; JavaScript `eval` in tooling.
- On a hit: Check what string reaches the call. If any part comes from input, a file or the network, reject the content.

<a id="rce.shell_true"></a>
### rce.shell_true

- Severity: `block` · Category: `rce` · OWASP LLM Top 10 (2025): LLM03:2025 Supply Chain
- Matches: `subprocess.run`, `call`, `check_output`, `check_call` or `Popen` with `shell=True` in the same call.
- Likely false positive: A fixed, constant command string run through the shell.
- On a hit: Ask for a list-argv call without the shell; reject it if user or model text reaches the command.

<a id="rce.shell_eval"></a>
### rce.shell_eval

- Severity: `block` · Category: `rce` · OWASP LLM Top 10 (2025): LLM03:2025 Supply Chain
- Matches: A shell `eval` at the start of a command (or after `;`, `&` or `|`) followed by a quote, `$` or a backtick.
- Likely false positive: Shell setup lines such as evaluating a tool's own init output.
- On a hit: Find what produces the evaluated string; only accept output of a trusted, pinned tool.

<a id="rce.pickle"></a>
### rce.pickle

- Severity: `block` · Category: `rce` · OWASP LLM Top 10 (2025): LLM03:2025 Supply Chain
- Matches: `pickle.load(s)`, `cPickle.load(s)` or `marshal.load(s)`.
- Likely false positive: Loading a cache file the tool itself wrote.
- On a hit: Unpickling runs code. Make sure the data can never come from outside; otherwise switch to JSON.

<a id="rce.dynamic_import"></a>
### rce.dynamic_import

- Severity: `warn` · Category: `rce` · OWASP LLM Top 10 (2025): LLM03:2025 Supply Chain
- Matches: `__import__(` or `importlib.import_module(`.
- Likely false positive: Plugin loaders that import modules from a fixed list.
- On a hit: Check where the module name comes from; a name built from input lets the content load arbitrary code.

<a id="exfil.secret_paths"></a>
### exfil.secret_paths

- Severity: `block` · Category: `exfil` · OWASP LLM Top 10 (2025): LLM02:2025 Sensitive Information Disclosure
- Matches: A reference to the `.ssh`, `.aws` or `.gnupg` directories, the AWS credentials file, or an `id_rsa` key name.
- Likely false positive: Setup docs inside a code fence that explain where a deploy key lives.
- On a hit: An agent tool has no reason to read key material. Reject unless the tool's stated purpose is key management.

<a id="exfil.dotenv"></a>
### exfil.dotenv

- Severity: `warn` · Category: `exfil` · OWASP LLM Top 10 (2025): LLM02:2025 Sensitive Information Disclosure
- Matches: A reference to a `.env` file (or `.env.something`).
- Likely false positive: Projects that document their own `.env.example`.
- On a hit: Check whether the content reads the file and sends it anywhere; reading plus egress is exfiltration.

<a id="exfil.secret_env_read"></a>
### exfil.secret_env_read

- Severity: `warn` · Category: `exfil` · OWASP LLM Top 10 (2025): LLM02:2025 Sensitive Information Disclosure
- Matches: Reading an environment variable whose name, within 30 characters, contains TOKEN, SECRET, API_KEY, ACCESS_KEY, PRIVATE_KEY or PASSWORD.
- Likely false positive: Any tool that authenticates with its own API key. This is why the rule only warns.
- On a hit: Fine on its own. Escalate only if the same code also sends data to a host the tool does not need.

<a id="exfil.secret_name"></a>
### exfil.secret_name

- Severity: `warn` · Category: `exfil` · OWASP LLM Top 10 (2025): LLM02:2025 Sensitive Information Disclosure
- Matches: An upper-case identifier ending in TOKEN, SECRET, API_KEY, ACCESS_KEY, PRIVATE_KEY or PASSWORD. Case-sensitive: lower-case identifiers such as `access_token` do not match.
- Likely false positive: Configuration docs naming the variable a user must set.
- On a hit: Review together with network findings; on its own it is informational.

<a id="exfil.keychain_read"></a>
### exfil.keychain_read

- Severity: `block` · Category: `exfil` · OWASP LLM Top 10 (2025): LLM02:2025 Sensitive Information Disclosure
- Matches: The macOS `security find-generic-password` or `find-internet-password` command.
- Likely false positive: A credential helper whose whole job is reading one named item.
- On a hit: Reject unless reading that exact keychain item is the tool's stated purpose.

<a id="exfil.keychain_mention"></a>
### exfil.keychain_mention

- Severity: `warn` · Category: `exfil` · OWASP LLM Top 10 (2025): LLM02:2025 Sensitive Information Disclosure
- Matches: The word `keychain`, or `security list-keychains`.
- Likely false positive: Documentation that mentions storing a token in the keychain.
- On a hit: Usually harmless; check that no keychain read follows.

<a id="exfil.net_lib"></a>
### exfil.net_lib

- Severity: `warn` · Category: `exfil` · OWASP LLM Top 10 (2025): LLM02:2025 Sensitive Information Disclosure
- Matches: A Python network library name: requests, urllib, urllib2, httplib, http.client, aiohttp or httpx.
- Likely false positive: Any tool that legitimately calls an API.
- On a hit: Check the hosts it talks to and what it sends; combined with secret reads, treat as exfiltration.

<a id="exfil.net_tool"></a>
### exfil.net_tool

- Severity: `warn` · Category: `exfil` · OWASP LLM Top 10 (2025): LLM02:2025 Sensitive Information Disclosure
- Matches: A network or copy tool used as a command: nc, netcat, telnet, scp, sftp or rsync followed by a space.
- Likely false positive: Deploy scripts that rsync build output.
- On a hit: Check the destination; a script in an agent skill rarely needs raw network tools.

<a id="destroy.rm_rf"></a>
### destroy.rm_rf

- Severity: `block` · Category: `destructive` · OWASP LLM Top 10 (2025): LLM06:2025 Excessive Agency
- Matches: A recursive, forced `rm` (`-rf`, `-fr`, `-r -f`, `--recursive --force`, in any order) whose target is `/`; a top-level system directory (`/etc`, `/usr`, `/bin`, `/sbin`, `/var`, `/opt`, `/private`, `/System`, `/Library`, `/home`, `/Users`, `/root`); `~`, `$HOME` or `${HOME}`; a credential directory in the home directory (`.ssh`, `.aws`, `.gnupg`, `.config`, `.kube`, `.docker`); or a glob over one of them or a bare `*`. Targets may be quoted and end in `/` or `/*`. Paths below those, such as temporary and build directories (`/tmp/x`, `$TMPDIR/x`, `/usr/local/x`, `./build`), do not match.
- Likely false positive: A script that empties its own working directory with a bare `*`.
- On a hit: Reject unless the path is a clearly scoped temporary directory.

<a id="destroy.disk"></a>
### destroy.disk

- Severity: `block` · Category: `destructive` · OWASP LLM Top 10 (2025): LLM06:2025 Excessive Agency
- Matches: `dd` with `of=` a `/dev` device other than `/dev/null`, `/dev/zero`, `/dev/stdout`, `/dev/stderr` or `/dev/fd/*`; `mkfs` (or `mkfs.<type>`) on a `/dev` device; or a redirect into a raw disk device. `dd` to a regular file does not match.
- Likely false positive: Disk-imaging tools whose purpose this is.
- On a hit: Never acceptable in agent content; reject.

<a id="destroy.forkbomb"></a>
### destroy.forkbomb

- Severity: `block` · Category: `destructive` · OWASP LLM Top 10 (2025): LLM06:2025 Excessive Agency
- Matches: The classic shell fork-bomb function definition.
- Likely false positive: Security training material quoting it.
- On a hit: Reject; there is no legitimate use inside agent content.

<a id="destroy.chmod_777"></a>
### destroy.chmod_777

- Severity: `warn` · Category: `destructive` · OWASP LLM Top 10 (2025): LLM06:2025 Excessive Agency
- Matches: `chmod 777` (optionally recursive, optionally with a leading 0).
- Likely false positive: Quick-start docs that loosen permissions on a scratch directory.
- On a hit: Ask for the narrowest mode that works; world-writable files let other users plant code.

## Text rules

Run on the full text of every file frisk reads, code files included, and on `--text` input. Markdown HTML comments, which renderers hide, are text-scanned like everything else.

<a id="inject.ignore_prev"></a>
### inject.ignore_prev

- Severity: `block` · Category: `injection` · OWASP LLM Top 10 (2025): LLM01:2025 Prompt Injection
- Matches: Text telling the reader to ignore all or the previous, prior, above or preceding instructions, prompts or context.
- Likely false positive: Security articles that quote the phrase as an example.
- On a hit: In content an agent will read, reject: it is an instruction-override attempt.

<a id="inject.disregard"></a>
### inject.disregard

- Severity: `block` · Category: `injection` · OWASP LLM Top 10 (2025): LLM01:2025 Prompt Injection
- Matches: The word disregard, optionally with all or the, directly followed by previous, prior, above or system.
- Likely false positive: Prose such as release notes that use the word in an unrelated sense.
- On a hit: Read the sentence in context; in a tool description or skill body, reject.

<a id="inject.fake_tool"></a>
### inject.fake_tool

- Severity: `warn` · Category: `injection` · OWASP LLM Top 10 (2025): LLM01:2025 Prompt Injection
- Matches: Markup that imitates a tool or function call: an opening angle bracket followed by `function_calls`, `tool_call`, `invoke` or an `antml:` tag.
- Likely false positive: Documentation of an agent framework that shows its own markup.
- On a hit: Content should not carry call markup the model could mistake for real tool output; remove it.

<a id="inject.role_override"></a>
### inject.role_override

- Severity: `warn` · Category: `injection` · OWASP LLM Top 10 (2025): LLM01:2025 Prompt Injection
- Matches: Chat-template control tokens that open a system turn.
- Likely false positive: Docs for a model-serving library.
- On a hit: Agent content has no reason to contain template tokens; remove or reject.

<a id="inject.exfil_instr"></a>
### inject.exfil_instr

- Severity: `warn` · Category: `injection` · OWASP LLM Top 10 (2025): LLM01:2025 Prompt Injection
- Matches: Text with any inflection of send, post, exfiltrate or upload (sends, sent, posted, uploading…), then `to`, then an http(s) URL, within short distances and with at most one line break (never across a blank line).
- Likely false positive: Docs telling a user to upload a file to the project's own site.
- On a hit: Check the URL and who the instruction is addressed to; an instruction to the model to send data out is hostile.

<a id="inject.hide_from_user"></a>
### inject.hide_from_user

- Severity: `block` · Category: `tool-poisoning` · OWASP LLM Top 10 (2025): LLM01:2025 Prompt Injection
- Matches: A do-not phrase (tell, inform, mention, reveal, notify or show) followed within 30 characters by the word user.
- Likely false positive: UI guidance that keeps raw stack traces out of the end user's view.
- On a hit: In a tool description or skill, reject: it asks the model to hide an action.

<a id="inject.hidden_important"></a>
### inject.hidden_important

- Severity: `warn` · Category: `tool-poisoning` · OWASP LLM Top 10 (2025): LLM01:2025 Prompt Injection
- Matches: An angle-bracket tag named IMPORTANT, SECRET or system_note (or system-note).
- Likely false positive: Docs that use such a tag for emphasis.
- On a hit: Read what the block asks for; hidden directive blocks are the usual tool-poisoning carrier.

<a id="inject.before_using"></a>
### inject.before_using

- Severity: `warn` · Category: `tool-poisoning` · OWASP LLM Top 10 (2025): LLM01:2025 Prompt Injection
- Matches: The word before, followed by using, calling, invoking or you use, and then within 40 characters by tool, function or this.
- Likely false positive: Normal prerequisites, such as setting an API key first.
- On a hit: Check whether the prerequisite is a side effect the model would perform (reading files, calling other tools).

<a id="inject.read_then_send"></a>
### inject.read_then_send

- Severity: `warn` · Category: `tool-poisoning` · OWASP LLM Top 10 (2025): LLM01:2025 Prompt Injection
- Matches: A read, cat or open verb within 40 characters of `.ssh`, `.aws`, `.env`, `id_rsa` or `credentials`.
- Likely false positive: Setup docs that tell a human where a cloud credential file lives.
- On a hit: If the text addresses the model, reject: it asks the model to read secrets.

## Instruction rules

Run on agent-instruction files only, where the text addresses the agent: `SKILL.md`, `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `*.mdc`, and `*.md` files in an `agents/` or `commands/` directory. Ordinary docs such as a README do not get them.

<a id="inject.sensitive_path_instruction"></a>
### inject.sensitive_path_instruction

- Severity: `block` · Category: `injection` · OWASP LLM Top 10 (2025): LLM01:2025 Prompt Injection
- Matches: An imperative verb (copy, send, upload, read, cat, include, attach or print) followed within 60 characters, in the same sentence, by a credential location: the `.ssh` directory or an `id_rsa`/`id_ed25519`-style private key (not a `.pub` key, `.ssh/config` or `known_hosts`), the AWS credentials file, the gcloud or Azure config directory, the `.gnupg` directory, a private key or the keychain. A clause that negates the verb first (never, not, no, avoid, don't) does not match, so a defensive "never read the SSH key" passes, also after an imperative sentence such as "Read the README."
- Likely false positive: A key-management skill whose stated job is to read a key.
- On a hit: Reject: an instruction file that tells the agent to read or send key material is an exfiltration attempt.

## Hidden characters

Run with the text rules.

<a id="unicode.invisible"></a>
### unicode.invisible

- Severity: `block` · Category: `obfuscation` · OWASP LLM Top 10 (2025): LLM01:2025 Prompt Injection
- Matches: Zero-width characters (space, joiner, non-joiner, word joiner), bidirectional controls (marks, embeddings, overrides, isolates) or tag characters (U+E0000 to U+E007F) anywhere in the text. A zero-width joiner directly between two emoji (as in a family emoji) and the tag sequence of one of the three recommended subdivision flags (England, Scotland, Wales: black flag, tag letters, cancel tag) are allowed; any other tag run blocks, since tag letters can spell hidden text a few at a time. Only the first reported occurrence of each character class is reported.
- Likely false positive: Text in right-to-left languages that uses directional marks on purpose.
- On a hit: Reveal the characters (for example with a hex view); hidden text an agent reads but a human does not see is a classic injection carrier.

<a id="unicode.hidden_format"></a>
### unicode.hidden_format

- Severity: `warn` · Category: `obfuscation` · OWASP LLM Top 10 (2025): LLM01:2025 Prompt Injection
- Matches: Invisible formatting characters that rarely belong in agent content: a run of two or more supplementary variation selectors (U+E0100 to U+E01EF), the invisible operators (U+2061 to U+2064), the soft hyphen (U+00AD), the Mongolian vowel separator (U+180E), or a byte-order mark (U+FEFF) anywhere but the very start of the text. A single variation selector and a leading byte-order mark are allowed. Only the first reported occurrence of each character class is reported.
- Likely false positive: Text copied from a word processor that inserted soft hyphens; ideographic variation sequences.
- On a hit: Reveal the characters (for example with a hex view); runs of variation selectors can encode hidden bytes.

## Coverage

Reported for content frisk could not pattern-match, so a scan is never PASS while executable content went unscanned. Media files (images, fonts, audio, video, PDF) are skipped silently and only counted in coverage.

<a id="coverage.binary"></a>
### coverage.binary

- Severity: `warn` · Category: `coverage` · OWASP LLM Top 10 (2025): LLM03:2025 Supply Chain
- Matches: A file frisk did not read as text because it is executable or archived: a native executable by its first bytes (ELF, Mach-O; checked only for a file that is not valid UTF-8 and has no code or text extension and no shebang), a shared library or binary module (.so, .dylib, .dll, .wasm, .exe, .node), compiled Python (.pyc, .pyo), Java bytecode (.jar, .class), or an archive (.zip, .tar, .gz, .tgz; reported as contents unscanned). The file is also listed in coverage.skipped with reason binary.
- Likely false positive: Prebuilt binaries a project ships on purpose, such as a vendored native extension, or a non-UTF-8 data file with NUL bytes and an extension frisk does not know.
- On a hit: frisk cannot see what the binary does. Build it from reviewed source, or scan the unpacked archive.

<a id="coverage.unreadable"></a>
### coverage.unreadable

- Severity: `warn` · Category: `coverage` · OWASP LLM Top 10 (2025): LLM03:2025 Supply Chain
- Matches: A file that could not be read (the error class is named, for example PermissionError) or is not valid UTF-8 (UnicodeDecodeError). Also a directory that could not be listed (its contents were not scanned). A non-UTF-8 file is still scanned with the undecodable bytes replaced, so one bad byte cannot hide a payload; a file with NUL bytes is matched twice, as written and with the NUL bytes dropped, and a finding from either counts once. Only media, executables, archives, opaque data formats (.bin, .dat, .db, .sqlite, .npy, .parquet) and non-UTF-8 files with NUL bytes and an unlisted extension are not scanned (media and non-UTF-8 opaque data silently, the others with coverage.binary). UTF-16 text is not decoded. The entry is also listed in coverage.skipped with reason unreadable.
- Likely false positive: A legacy Latin-1 encoded script or document.
- On a hit: Re-encode the file as UTF-8 and scan again; one invalid byte must not be allowed to hide a payload.

<a id="coverage.nested_vcs"></a>
### coverage.nested_vcs

- Severity: `warn` · Category: `coverage` · OWASP LLM Top 10 (2025): LLM03:2025 Supply Chain
- Matches: A .git directory below the top of the scanned target. Like the top-level one it is not scanned (it is listed in coverage.skipped as vcs_dir with detail nested), but content placed there can be referenced from files that are scanned, so it warns.
- Likely false positive: Vendored dependencies checked in with their own repository metadata.
- On a hit: Check that nothing outside the directory refers into it; remove vendored .git directories.

<a id="coverage.surface_error"></a>
### coverage.surface_error

- Severity: `warn` · Category: `coverage` · OWASP LLM Top 10 (2025): LLM03:2025 Supply Chain
- Matches: One of frisk's scan surfaces (src/frisk/surfaces/) raised an error on a file. The other surfaces still ran on it and every other file was scanned; the file is also listed in coverage.skipped with reason surface_error and the surface named in detail.
- Likely false positive: None expected: this signals a bug in frisk, not in the content.
- On a hit: Report it, and review the file by hand until a fixed frisk scans it cleanly.
