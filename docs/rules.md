# frisk rule reference

One section per rule id. Each anchor equals the id exactly, so `docs/rules.md#<rule-id>` links
(SARIF `helpUri`) resolve. Payloads are described in words; this page contains none.
`tests/test_rules_doc.py` fails when a rule in `src/frisk/rules.py` has no section here,
or when a section's severity or category disagrees with the code.

Severity: **block** fails a scan by default; **warn** fails only with `--fail-on warn`.

## Code rules

Run on script files (`.py`, `.sh`, `.js` and the other code extensions) and on fenced code blocks in every other text file.

<a id="rce.pipe_installer"></a>
### rce.pipe_installer

- Severity: `block` · Category: `rce` · OWASP LLM Top 10 (2025): LLM03:2025 Supply Chain
- Matches: A `curl` or `wget` command whose output is piped, on the same line, into a shell or a Python interpreter (optionally through `sudo`).
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
- Matches: An upper-case identifier ending in TOKEN, SECRET, API_KEY, ACCESS_KEY, PRIVATE_KEY or PASSWORD.
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
- Matches: A recursive, forced `rm` whose target is `/`, `~`, `$HOME` or a glob.
- Likely false positive: Cleanup of a build directory written with a glob.
- On a hit: Reject unless the path is a clearly scoped temporary directory.

<a id="destroy.disk"></a>
### destroy.disk

- Severity: `block` · Category: `destructive` · OWASP LLM Top 10 (2025): LLM06:2025 Excessive Agency
- Matches: `dd if=`, `mkfs`, or a redirect into a raw disk device.
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

Run on the full text of every file frisk reads, code files included, and on `--text` input.

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
- Matches: Text with send, post, exfiltrate or upload, then `to`, then an http(s) URL, all on one line within short distances.
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

## Hidden characters

Run with the text rules.

<a id="unicode.invisible"></a>
### unicode.invisible

- Severity: `block` · Category: `obfuscation` · OWASP LLM Top 10 (2025): LLM01:2025 Prompt Injection
- Matches: Zero-width characters (space, joiner, non-joiner, word joiner) or bidirectional controls (marks, embeddings, overrides, isolates) anywhere in the text. A byte-order mark is allowed only as the first character. Only the first occurrence of each character is reported.
- Likely false positive: Text in right-to-left languages that uses directional marks on purpose.
- On a hit: Reveal the characters (for example with a hex view); hidden text an agent reads but a human does not see is a classic injection carrier.

## Coverage

Reported for content frisk could not pattern-match, so a scan is never PASS while executable content went unscanned. Media files (images, fonts, audio, video, PDF) are skipped silently and only counted in coverage.

<a id="coverage.binary"></a>
### coverage.binary

- Severity: `warn` · Category: `coverage` · OWASP LLM Top 10 (2025): LLM03:2025 Supply Chain
- Matches: A file frisk did not read as text because it is executable or archived: a native executable by its first bytes (ELF, Mach-O), a shared library or binary module (.so, .dylib, .dll, .wasm, .exe, .node), compiled Python (.pyc, .pyo), Java bytecode (.jar, .class), or an archive (.zip, .tar, .gz, .tgz; reported as contents unscanned). The file is also listed in coverage.skipped with reason binary.
- Likely false positive: Prebuilt binaries a project ships on purpose, such as a vendored native extension.
- On a hit: frisk cannot see what the binary does. Build it from reviewed source, or scan the unpacked archive.

<a id="coverage.unreadable"></a>
### coverage.unreadable

- Severity: `warn` · Category: `coverage` · OWASP LLM Top 10 (2025): LLM03:2025 Supply Chain
- Matches: A code or text file (by extension, or any file starting with a shebang) that could not be read (the error class is named, for example PermissionError) or is not valid UTF-8 (UnicodeDecodeError), or a directory that could not be listed (its contents were not scanned). The entry is also listed in coverage.skipped with reason unreadable.
- Likely false positive: A legacy Latin-1 encoded script or document.
- On a hit: Re-encode the file as UTF-8 and scan again; one invalid byte must not be allowed to hide a payload.
