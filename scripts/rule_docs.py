"""The prose of docs/rules.md, keyed by rule id: scripts/gen_rules_doc.py renders it with
each rule's id, severity, category, contexts and OWASP entry, which come from src/frisk/rules.py.

Every rule frisk can report has one entry (tests/test_rule_metadata.py). Payloads are
described in words: no field holds a hidden character, `why` and `example` match no rule's
pattern, and the rendered docs/rules.md, scanned by frisk as a file, has no block finding.
This file is documentation, not part of the frisk package: frisk never imports it.
"""
from __future__ import annotations

from typing import NamedTuple


class RuleDoc(NamedTuple):
    matches: str         # what the rule matches, in words
    why: str             # the rationale: why a hit matters
    example: str         # one sentence describing content that hits it, in words
    false_positive: str  # when legitimate content triggers it, and how to tell
    on_hit: str          # what to do about a hit


# Each section's opening paragraph, by section title (gen_rules_doc.SECTIONS orders them).
SECTION_INTROS: dict[str, str] = {
    "Code rules": ("Run on script files (`.py`, `.sh`, `.js`, `.tsx` and the other code extensions, or any "
                   "file whose first line is a `#!` shebang), on fenced code blocks (` ``` ` or `~~~`, any "
                   "length; an unclosed fence runs to the end of the file) in every other text file, on "
                   "indented code blocks and inline code spans in markdown (`.md`, `.markdown`, `.mdc`), and "
                   "on the shell commands in build files: Makefile recipe lines (`Makefile`, `GNUmakefile`, "
                   "`*.mk`), Dockerfile `RUN` instructions (`Dockerfile`, `Dockerfile.*`, `*.dockerfile`), "
                   "justfile recipe lines and the `scripts` values of `package.json`. Backslash-continued "
                   "lines belong to their command. In a `.json` file, the decoded value of a `command`, `run`, "
                   "`script`, `shell` or `exec` key (an array of strings under one is joined with spaces), an "
                   "`args` array joined after its object's `command`, and any other string value holding a "
                   "shell pipeline are code too; a finding is reported at the line of the string (for a join, "
                   "of the command).\n\nInline code spans in an ordinary markdown document (a README, `docs/`, "
                   "any `.md` or `.markdown` that is not an agent-instruction file) report a code rule at most "
                   "as `warn`: a document that mentions a risky call by name is not running it. In "
                   "agent-instruction files (see "
                   "[inject.sensitive_path_instruction](#inject.sensitive_path_instruction) for the list) and "
                   "in fenced or indented code blocks everywhere, code rules keep the severity listed below. "
                   "Text rules keep their severity in every form."),
    "Text rules": ("Run on the full text of every file frisk reads, code files included, and on `--text` "
                   "input. Markdown HTML comments, which renderers hide, are text-scanned like everything "
                   "else. Each string of a `.json` file written with a backslash escape is also scanned as the "
                   "text it decodes to, and reported at its line."),
    "Instruction rules": ("Run on agent-instruction files only, where the text addresses the agent: "
                          "`SKILL.md`, `CLAUDE.md`, `CLAUDE.local.md`, `AGENTS.md`, `.cursorrules`, `*.mdc`, "
                          "`*.md` files in an `agents/` or `commands/` directory, and `*.md` files at any "
                          "depth below `.claude/agents`, `.claude/commands`, `.claude/rules`, `.claude/skills` "
                          "or `.claude/output-styles`. Names match in any case. Ordinary docs such as a README "
                          "do not get them."),
    "Prose rules": ("Run only where text is scanned as a string in a context (`engine.scan_text`). `frisk "
                    "proxy` scans tool definitions, prompt and resource listing entries, the server's "
                    "`instructions` and elicitation requests (the server's own text to the user) as "
                    "`tool_description`, and everything else the model reads (tool results and their "
                    "structured content, `prompts/get` messages, `resources/read` contents, error answers, "
                    "sampling requests) as `tool_result`. `tool_description` runs the text rules, "
                    "`rce.pipe_installer`, `exfil.keychain_read`, `destroy.rm_rf`, `destroy.disk`, "
                    "`destroy.forkbomb`, "
                    "[inject.sensitive_path_instruction](#inject.sensitive_path_instruction), the "
                    "hidden-Unicode check and the two rules below; `tool_result` runs the text rules, "
                    "inject.sensitive_path_instruction, `rce.pipe_installer`, `exfil.keychain_read`, "
                    "`destroy.rm_rf`, `destroy.disk`, `destroy.forkbomb` and the hidden-Unicode check (no "
                    "other code rule: a result may quote code, such as a file that calls `eval`); `default` "
                    "(`--text` and frisk-mcp's `scan_text`) runs every code and text rule and the "
                    "hidden-Unicode check. Files are not scanned with these."),
    "Hidden characters": "Run with the text rules.",
    "Coverage": ("Reported for content frisk could not pattern-match, so a scan is never PASS while executable "
                 "content went unscanned. Media files (images, fonts, audio, video, PDF) are skipped silently "
                 "and only counted in coverage, unless their first bytes are text."),
}

RULE_DOCS: dict[str, RuleDoc] = {
    "rce.pipe_installer": RuleDoc(
        matches=("A `curl` or `wget` command whose output is piped into a shell or a Python interpreter on the "
                 "same line or across backslash-continued lines (before or after the `|`), where the shell may "
                 "be named by a path (`/bin/sh`) or reached through `sudo` or `env` with options; or a "
                 "`curl`/`wget` download run by a shell through process substitution (`bash <(…)`) or `sh -c "
                 "\"$(…)\"`."),
        why=("Piping a download straight into an interpreter runs whatever the server sends at that moment, "
             "unreviewed and unpinned, so the code that runs can change at any time."),
        example=("A setup step that downloads an install script from a web server and feeds it directly to the "
                 "shell, in one command line."),
        false_positive=("Install instructions in a README that tell a human to run a vendor's official "
                        "installer."),
        on_hit="Do not run it. Download the script, read it, and pin it by hash; prefer a package manager.",
    ),
    "rce.eval_b64": RuleDoc(
        matches=("A call to `eval` or `exec` whose arguments decode base64 inside the same parentheses, within "
                 "400 characters of the call."),
        why=("Encoding code as base64 and evaluating it at run time hides what the code does from a reader and "
             "from pattern scanners."),
        example=("A Python helper that decodes a long base64 string and passes the result straight to the "
                 "built-in evaluator."),
        false_positive="Rare. Test code that exercises a decoder through `eval`.",
        on_hit="Treat as hostile: decode the payload offline (never execute it) and see what it does.",
    ),
    "rce.python_exec": RuleDoc(
        matches=("A bare `exec(` or `eval(` call (not a method such as `re.exec`), or `os.system(` / "
                 "`os.popen(`."),
        why=("Evaluating a string, or handing it to the system shell, runs code that is not in the file, often "
             "built from input."),
        example=("A tool function that joins a user-supplied file name into a command string and runs it "
                 "through the operating system's shell call."),
        false_positive=("Build scripts that call `os.system` with a fixed command; JavaScript `eval` in "
                        "tooling."),
        on_hit=("Check what string reaches the call. If any part comes from input, a file or the network, "
                "reject the content."),
    ),
    "rce.shell_true": RuleDoc(
        matches=("`subprocess.run`, `call`, `check_output`, `check_call` or `Popen` with `shell=True` in the "
                 "same call, within 400 characters of it."),
        why=("With the shell turned on, any quote, semicolon or dollar sign that reaches the command string "
             "becomes shell syntax: command injection."),
        example=("A server that builds a git command from a tool argument and starts it as a child process "
                 "with the shell option enabled."),
        false_positive="A fixed, constant command string run through the shell.",
        on_hit=("Ask for a list-argv call without the shell; reject it if user or model text reaches the "
                "command."),
    ),
    "rce.shell_eval": RuleDoc(
        matches=("A shell `eval` at the start of a command (or after `;`, `&` or `|`) followed by a quote, `$` "
                 "or a backtick."),
        why="A shell that evaluates a computed string runs code that exists only at run time.",
        example=("A shell script that downloads a value into a variable and then evaluates the variable's "
                 "contents as a command."),
        false_positive="Shell setup lines such as evaluating a tool's own init output.",
        on_hit="Find what produces the evaluated string; only accept output of a trusted, pinned tool.",
    ),
    "rce.pickle": RuleDoc(
        matches="`pickle.load(s)`, `cPickle.load(s)` or `marshal.load(s)`.",
        why="Unpickling or unmarshalling data can run arbitrary code chosen by whoever wrote the data.",
        example=("A server that loads a cached object from its download directory with Python's object "
                 "deserializer."),
        false_positive="Loading a cache file the tool itself wrote.",
        on_hit=("Unpickling runs code. Make sure the data can never come from outside; otherwise switch to "
                "JSON."),
    ),
    "rce.dynamic_import": RuleDoc(
        matches="`__import__(` or `importlib.import_module(`.",
        why=("Importing a module by a computed name lets the content load code that a reader of the file "
             "cannot see."),
        example="A plugin loader that takes a module name from a tool argument and imports it.",
        false_positive="Plugin loaders that import modules from a fixed list.",
        on_hit=("Check where the module name comes from; a name built from input lets the content load "
                "arbitrary code."),
    ),
    "exfil.secret_paths": RuleDoc(
        matches=("A reference to the `.ssh`, `.aws` or `.gnupg` directories, the AWS credentials file, or an "
                 "`id_rsa` key name."),
        why=("SSH keys, cloud credentials and GPG keyrings are the most valuable files on a developer machine; "
             "agent content rarely has a reason to touch them."),
        example=("A script that lists the files in the user's SSH key directory and copies them into a temp "
                 "folder."),
        false_positive="Setup docs inside a code fence that explain where a deploy key lives.",
        on_hit=("An agent tool has no reason to read key material. Reject unless the tool's stated purpose is "
                "key management."),
    ),
    "exfil.dotenv": RuleDoc(
        matches="A reference to a `.env` file (or `.env.something`).",
        why="Dotenv files hold a project's API keys and database passwords in plain text.",
        example="A tool that loads the project's dotenv file and includes its lines in its output.",
        false_positive="Projects that document their own `.env.example`.",
        on_hit=("Check whether the content reads the file and sends it anywhere; reading plus egress is "
                "exfiltration."),
    ),
    "exfil.secret_env_read": RuleDoc(
        matches=("Reading an environment variable whose name, within 30 characters, contains TOKEN, SECRET, "
                 "API_KEY, ACCESS_KEY, PRIVATE_KEY or PASSWORD."),
        why=("Environment variables are where tokens live: reading one is normal for authentication, and it is "
             "also the first half of a token theft."),
        example="A server that takes its vendor API token from the environment to call the vendor's API.",
        false_positive="Any tool that authenticates with its own API key. This is why the rule only warns.",
        on_hit=("Fine on its own. Escalate only if the same code also sends data to a host the tool does not "
                "need."),
    ),
    "exfil.secret_name": RuleDoc(
        matches=("An upper-case identifier ending in TOKEN, SECRET, API_KEY, ACCESS_KEY, PRIVATE_KEY or "
                 "PASSWORD. Case-sensitive: lower-case identifiers such as `access_token` do not match."),
        why=("A secret-bearing variable name shows where the content handles credentials, which is worth a "
             "look together with any network code."),
        example="A config template that names an upper-case variable ending in the word for an access token.",
        false_positive="Configuration docs naming the variable a user must set.",
        on_hit="Review together with network findings; on its own it is informational.",
    ),
    "exfil.keychain_read": RuleDoc(
        matches="The macOS `security find-generic-password` or `find-internet-password` command.",
        why=("The macOS command-line password lookup returns a stored password in clear text to whoever runs "
             "it."),
        example=("A script that asks the macOS password store, from the command line, for the saved password "
                 "of a named web site."),
        false_positive="A credential helper whose whole job is reading one named item.",
        on_hit="Reject unless reading that exact keychain item is the tool's stated purpose.",
    ),
    "exfil.keychain_mention": RuleDoc(
        matches="The word `keychain`, or `security list-keychains`.",
        why=("Mentioning the macOS password store is usually harmless, but it marks content that deals with "
             "stored credentials."),
        example="Documentation saying that a token is saved in the macOS password store.",
        false_positive="Documentation that mentions storing a token in the keychain.",
        on_hit="Usually harmless; check that no keychain read follows.",
    ),
    "exfil.net_lib": RuleDoc(
        matches=("A Python network library name: requests, urllib, urllib2, httplib, http.client, aiohttp or "
                 "httpx."),
        why=("Network access from a script is how stolen data leaves the machine; it matters most next to "
             "secret reads."),
        example="A Python tool that imports an HTTP client library to call a weather API.",
        false_positive="Any tool that legitimately calls an API.",
        on_hit=("Check the hosts it talks to and what it sends; combined with secret reads, treat as "
                "exfiltration."),
    ),
    "exfil.net_tool": RuleDoc(
        matches=("A network or copy tool used as a command: nc, netcat, telnet, scp, sftp or rsync followed by "
                 "a space."),
        why="Raw network and copy tools move files to another host with no API in between.",
        example="A shell script that opens a raw TCP connection to a remote host and writes a file into it.",
        false_positive="Deploy scripts that rsync build output.",
        on_hit="Check the destination; a script in an agent skill rarely needs raw network tools.",
    ),
    "destroy.rm_rf": RuleDoc(
        matches=("A recursive, forced `rm` (`-rf`, `-fr`, `-r -f`, `--recursive --force`, in any order; the "
                 "flags and the target anywhere in the next 256 words of the same command) whose target is "
                 "`/`; a top-level system directory (`/etc`, `/usr`, `/bin`, `/sbin`, `/var`, `/opt`, "
                 "`/private`, `/System`, `/Library`, `/home`, `/Users`, `/root`); `~`, `$HOME` or `${HOME}`; a "
                 "credential directory in the home directory (`.ssh`, `.aws`, `.gnupg`, `.config`, `.kube`, "
                 "`.docker`); or a glob over one of them or a bare `*`. Targets may be quoted and end in `/` "
                 "or `/*`. Paths below those, such as temporary and build directories (`/tmp/x`, `$TMPDIR/x`, "
                 "`/usr/local/x`, `./build`), do not match. One finding per command, at its first `rm` word."),
        why=("A forced recursive delete of the root, a system directory or the home directory destroys data "
             "that cannot be recovered."),
        example="A cleanup step that force-deletes the user's whole home directory, recursively.",
        false_positive="A script that empties its own working directory with a bare `*`.",
        on_hit="Reject unless the path is a clearly scoped temporary directory.",
    ),
    "destroy.disk": RuleDoc(
        matches=("`dd` with `of=` a `/dev` device other than `/dev/null`, `/dev/zero`, `/dev/stdout`, "
                 "`/dev/stderr` or `/dev/fd/*`; `mkfs` (or `mkfs.<type>`) on a `/dev` device; or a redirect "
                 "into a raw disk device. `dd` to a regular file does not match."),
        why="Writing raw bytes to a disk device, or formatting it, wipes every file system on it.",
        example="A script that writes zeros directly onto the machine's first disk device.",
        false_positive="Disk-imaging tools whose purpose this is.",
        on_hit="Never acceptable in agent content; reject.",
    ),
    "destroy.forkbomb": RuleDoc(
        matches="The classic shell fork-bomb function definition.",
        why="A fork bomb spawns processes until the machine stops responding.",
        example="A one-line shell function that starts two background copies of itself, forever.",
        false_positive="Security training material quoting it.",
        on_hit="Reject; there is no legitimate use inside agent content.",
    ),
    "destroy.chmod_777": RuleDoc(
        matches="`chmod 777` (optionally recursive, optionally with a leading 0).",
        why=("World-writable files and directories let any local user or process replace their contents with "
             "code."),
        example="An install step that makes the tool's whole install directory writable by every user.",
        false_positive="Quick-start docs that loosen permissions on a scratch directory.",
        on_hit="Ask for the narrowest mode that works; world-writable files let other users plant code.",
    ),
    "inject.ignore_prev": RuleDoc(
        matches=("Text telling the reader to ignore all or the previous, prior, above or preceding "
                 "instructions, prompts or context."),
        why=("The classic instruction override: text the model reads tries to cancel the user's and the "
             "system's instructions."),
        example=("A tool description that tells the model to forget everything it was told so far and follow "
                 "new orders instead."),
        false_positive="Security articles that quote the phrase as an example.",
        on_hit="In content an agent will read, reject: it is an instruction-override attempt.",
    ),
    "inject.disregard": RuleDoc(
        matches=("The word disregard, optionally with all or the, directly followed by previous, prior, above "
                 "or system."),
        why="Another form of the instruction override, aimed at the system prompt or the earlier context.",
        example="A skill body that tells the model to set its system prompt aside.",
        false_positive="Prose such as release notes that use the word in an unrelated sense.",
        on_hit="Read the sentence in context; in a tool description or skill body, reject.",
    ),
    "inject.fake_tool": RuleDoc(
        matches=("Markup that imitates a tool or function call: an opening angle bracket followed by "
                 "`function_calls`, `tool_call`, `invoke` or an `antml:` tag."),
        why=("Markup that looks like a tool call or tool output can make the model believe a call happened, or "
             "must happen."),
        example="A web page holding text dressed up as the model's own function-call markup.",
        false_positive="Documentation of an agent framework that shows its own markup.",
        on_hit="Content should not carry call markup the model could mistake for real tool output; remove it.",
    ),
    "inject.role_override": RuleDoc(
        matches="Chat-template control tokens that open a system turn.",
        why="Chat-template control tokens can open a fake system turn inside ordinary content.",
        example=("A document that embeds the special tokens a model's chat template uses to start a system "
                 "message."),
        false_positive="Docs for a model-serving library.",
        on_hit="Agent content has no reason to contain template tokens; remove or reject.",
    ),
    "inject.exfil_instr": RuleDoc(
        matches=("Text with any inflection of send, post, exfiltrate or upload (sends, sent, posted, "
                 "uploading…), then `to`, then an http(s) URL, within short distances and with at most one "
                 "line break (never across a blank line)."),
        why="An instruction to send data to a URL is the delivery step of an exfiltration.",
        example="A tool description that tells the model to post the whole conversation to a web address.",
        false_positive="Docs telling a user to upload a file to the project's own site.",
        on_hit=("Check the URL and who the instruction is addressed to; an instruction to the model to send "
                "data out is hostile."),
    ),
    "inject.hide_from_user": RuleDoc(
        matches=("A do-not phrase (tell, inform, mention, reveal, notify or show) followed within 30 "
                 "characters by the word user."),
        why="Content that asks the model to keep an action secret from the user is hiding what it does.",
        example="A tool description that asks the model to stay silent about an upload it performs.",
        false_positive="UI guidance that keeps raw stack traces out of the end user's view.",
        on_hit="In a tool description or skill, reject: it asks the model to hide an action.",
    ),
    "inject.hidden_important": RuleDoc(
        matches="An angle-bracket tag named IMPORTANT, SECRET or system_note (or system-note).",
        why=("Tags such as IMPORTANT set hidden directives apart so the model gives them weight; they are the "
             "usual wrapper of a tool-poisoning attack."),
        example=("A tool description whose visible first line is harmless, followed by an angle-bracket block "
                 "of extra orders for the model."),
        false_positive="Docs that use such a tag for emphasis.",
        on_hit="Read what the block asks for; hidden directive blocks are the usual tool-poisoning carrier.",
    ),
    "inject.before_using": RuleDoc(
        matches=("The word before, followed by using, calling, invoking or you use, and then within 40 "
                 "characters by tool, function or this."),
        why="A prerequisite attached to a tool's use can make the model perform a side effect on every call.",
        example=("A tool description that tells the model to run a different tool first, every time, and pass "
                 "along what it returned."),
        false_positive="Normal prerequisites, such as setting an API key first.",
        on_hit=("Check whether the prerequisite is a side effect the model would perform (reading files, "
                "calling other tools)."),
    ),
    "inject.read_then_send": RuleDoc(
        matches=("A read, cat or open verb within 40 characters of `.ssh`, `.aws`, `.env`, `id_rsa` or "
                 "`credentials`."),
        why="Pointing the model at a credential file is the first half of a tool-poisoning theft.",
        example="A tool description that asks the model to look inside the user's cloud key file.",
        false_positive="Setup docs that tell a human where a cloud credential file lives.",
        on_hit="If the text addresses the model, reject: it asks the model to read secrets.",
    ),
    "inject.sensitive_path_instruction": RuleDoc(
        matches=("An imperative verb (copy, send, upload, read, cat, include, attach or print) followed within "
                 "60 characters, in the same sentence, by a credential location: the `.ssh` directory or an "
                 "`id_rsa`/`id_ed25519`-style private key (not a `.pub` key, `.ssh/config` or `known_hosts`), "
                 "the AWS credentials file, the gcloud or Azure config directory, the `.gnupg` directory, a "
                 "private key or the keychain. A clause that negates the verb first (never, not, no, avoid, "
                 "don't) does not match, so a defensive \"never read the SSH key\" passes, also after an "
                 "imperative sentence such as \"Read the README.\""),
        why=("An agent-instruction file speaks to the agent with the user's authority, so an order in it to "
             "hand over key material is carried out."),
        example="A skill file that tells the agent to attach the user's SSH signing key to a bug report.",
        false_positive="A key-management skill whose stated job is to read a key.",
        on_hit=("Reject: an instruction file that tells the agent to read or send key material is an "
                "exfiltration attempt."),
    ),
    "exfil.secret_paths_prose": RuleDoc(
        matches=("The pattern of [exfil.secret_paths](#exfil.secret_paths) (the `.ssh`, `.aws` or `.gnupg` "
                 "directory, the AWS credentials file, `id_rsa`) in a tool description, where it names a path "
                 "rather than reading one."),
        why=("A tool that names a credential directory may need it (an SSH host lister does), but a reviewer "
             "should know."),
        example="A tool description saying that it lists the hosts in the user's SSH client configuration.",
        false_positive="A tool that reports on SSH hosts from `~/.ssh/config` or manages AWS profiles.",
        on_hit=("Check that the tool's job needs the path. An instruction to read or send a key from it blocks "
                "as inject.sensitive_path_instruction, and a private key or credential file named in the "
                "description blocks as [exfil.secret_files_prose](#exfil.secret_files_prose); either way the "
                "tool is dropped."),
    ),
    "exfil.secret_files_prose": RuleDoc(
        matches=("A private key or credential file in a tool description: `id_rsa`, `id_dsa`, `id_ecdsa` or "
                 "`id_ed25519` (not the `.pub` public key), the AWS credentials file, or the `.gnupg` "
                 "directory, however the description asks for it (an instruction that uses another verb than "
                 "inject.sensitive_path_instruction's, or a negation word such as \"don't forget to\", is still "
                 "caught)."),
        why=("A tool description has no harmless reason to name a key file or the cloud credentials file, "
             "however it phrases the request."),
        example=("A tool description that reminds the model to bring along the user's default SSH identity "
                 "file."),
        false_positive="A key-management tool that names the key file it generates or rotates.",
        on_hit=("The tool is dropped. Keep it only if handling that exact file is the tool's stated purpose, "
                "and the server is one you trust."),
    ),
    "unicode.invisible": RuleDoc(
        matches=("Zero-width characters (space, joiner, non-joiner, word joiner), bidirectional controls "
                 "(marks, embeddings, overrides, isolates) or tag characters (U+E0000 to U+E007F) anywhere in "
                 "the text. A zero-width joiner directly between two emoji (as in a family emoji) and the tag "
                 "sequence of one of the three recommended subdivision flags (England, Scotland, Wales: black "
                 "flag, tag letters, cancel tag) are allowed; any other tag run blocks, since tag letters can "
                 "spell hidden text a few at a time. Only the first reported occurrence of each character "
                 "class is reported."),
        why=("Invisible and direction-changing characters let text say one thing to the model and show another "
             "to a human."),
        example=("A tool description with a hidden sentence spelled in zero-width characters between two "
                 "visible words."),
        false_positive="Text in right-to-left languages that uses directional marks on purpose.",
        on_hit=("Reveal the characters (for example with a hex view); hidden text an agent reads but a human "
                "does not see is a classic injection carrier."),
    ),
    "unicode.hidden_format": RuleDoc(
        matches=("Invisible formatting characters that rarely belong in agent content: a run of two or more "
                 "supplementary variation selectors (U+E0100 to U+E01EF), the invisible operators (U+2061 to "
                 "U+2064), the soft hyphen (U+00AD), the Mongolian vowel separator (U+180E), or a byte-order "
                 "mark (U+FEFF) anywhere but the very start of the text. A single variation selector and a "
                 "leading byte-order mark are allowed. Only the first reported occurrence of each character "
                 "class is reported."),
        why="Rare formatting characters can carry hidden data, or split words so that patterns miss them.",
        example=("A skill file with a long run of variation selectors after one letter, encoding bytes a "
                 "reader cannot see."),
        false_positive=("Text copied from a word processor that inserted soft hyphens; ideographic variation "
                        "sequences."),
        on_hit=("Reveal the characters (for example with a hex view); runs of variation selectors can encode "
                "hidden bytes."),
    ),
    "coverage.binary": RuleDoc(
        matches=("A file frisk did not read as text because it is executable or archived: a native executable "
                 "by its first bytes (ELF, Mach-O; checked only for a file that is not valid UTF-8 and has no "
                 "code or text extension and no shebang), a shared library or binary module (.so, .dylib, "
                 ".dll, .wasm, .exe, .node), compiled Python (.pyc, .pyo), Java bytecode (.jar, .class), or an "
                 "archive (.zip, .tar, .gz, .tgz; reported as contents unscanned). The file is also listed in "
                 "coverage.skipped with reason binary."),
        why=("frisk cannot see inside compiled or archived code, so a clean verdict would claim more than it "
             "checked."),
        example="A plugin that ships a prebuilt native library next to its scripts.",
        false_positive=("Prebuilt binaries a project ships on purpose, such as a vendored native extension, or "
                        "a non-UTF-8 data file with NUL bytes and an extension frisk does not know."),
        on_hit=("frisk cannot see what the binary does. Build it from reviewed source, or scan the unpacked "
                "archive."),
    ),
    "coverage.unreadable": RuleDoc(
        matches=("A file that could not be read (the error class is named, for example PermissionError) or is "
                 "not valid UTF-8 (UnicodeDecodeError). Also a directory that could not be listed (its "
                 "contents were not scanned). A non-UTF-8 file is still scanned with the undecodable bytes "
                 "replaced, so one bad byte cannot hide a payload; a file with NUL bytes is matched twice, as "
                 "written and with the NUL bytes dropped, and a finding from either counts once. Only media, "
                 "executables, archives, opaque data formats (.bin, .dat, .db, .sqlite, .npy, .parquet) and "
                 "non-UTF-8 files with NUL bytes and an unlisted extension are not scanned (media and "
                 "non-UTF-8 opaque data silently, the others with coverage.binary); a media file whose "
                 "first bytes are text is scanned. UTF-16 text is not "
                 "decoded. The entry is also listed in coverage.skipped with reason unreadable."),
        why=("A file that cannot be read, or reads only with replaced bytes, may hold content frisk did not "
             "match."),
        example="A script saved in a legacy single-byte encoding.",
        false_positive="A legacy Latin-1 encoded script or document.",
        on_hit=("Re-encode the file as UTF-8 and scan again; one invalid byte must not be allowed to hide a "
                "payload."),
    ),
    "coverage.nested_vcs": RuleDoc(
        matches=("A .git directory below the top of the scanned target. Like the top-level one it is not "
                 "scanned (it is listed in coverage.skipped as vcs_dir with detail nested), but content placed "
                 "there can be referenced from files that are scanned, so it warns."),
        why=("A repository inside the target can hold content that scanned files refer to but frisk does not "
             "read."),
        example="A vendored dependency checked in with its own git directory.",
        false_positive="Vendored dependencies checked in with their own repository metadata.",
        on_hit="Check that nothing outside the directory refers into it; remove vendored .git directories.",
    ),
    "coverage.surface_error": RuleDoc(
        matches=("One of frisk's scan surfaces (src/frisk/surfaces/) raised an error on a file. The other "
                 "surfaces still ran on it and every other file was scanned; the file is also listed in "
                 "coverage.skipped with reason surface_error and the surface named in detail."),
        why=("A failed surface means part of a file may not have been matched; the scan says so instead of "
             "passing."),
        example="A JSON file whose structure trips a bug in one of frisk's surfaces.",
        false_positive="None expected: this signals a bug in frisk, not in the content.",
        on_hit="Report it, and review the file by hand until a fixed frisk scans it cleanly.",
    ),
    "coverage.unscanned": RuleDoc(
        matches=("Content frisk did not scan. The rest of a directory tree once a scan limit was hit: 20,000 "
                 "files (`file_cap`), and in frisk-mcp also a byte total (`byte_cap`) or a time limit "
                 "(`deadline`), reported at the target with the files scanned before it. And an MCP server in "
                 "an audited config (`--mcp-config`, or a config file named as a target) that frisk did not "
                 "scan: a remote server (`url`), an npx/uvx/pipx package that is not in the local cache (or "
                 "whose cache entry is unusable, or of which several versions are cached and none is pinned), "
                 "a package run by another runner, a server whose source could not be resolved (for example a "
                 "relative script with no `cwd`), a console-script wrapper or bin shim whose package is not "
                 "scanned (`wrapper`), or an entry that is not a valid server (`invalid`). One warning per "
                 "server, plus one for a remote URL an entry names beside its command (the command itself is "
                 "scanned), at `name::<location>` (the location as the audit prints it: a URL by its scheme, "
                 "host and port only). So an audit with a skipped server is never PASS, and the text report "
                 "says how many servers were not scanned."),
        why="A server or a tree that frisk did not read cannot be called clean.",
        example="An MCP config entry that runs an npm package which is not in the local npx cache.",
        false_positive=("A remote server you trust, or a package you vetted some other way. The warning "
                        "reports missing coverage, not malicious content."),
        on_hit=("Do not run an unvetted package to get it cached. Scan its source instead: its repository with "
                "`frisk <git URL>`, or a downloaded copy (for example the unpacked `npm pack <pkg>` tarball). "
                "Pin a version in the config so a later audit matches the cached copy, and give a local server "
                "an absolute path or `cwd`. Review remote servers by other means."),
    ),
    "coverage.too_large": RuleDoc(
        matches=("A file over the size limit (`--max-file-bytes`, default 2 MiB), which frisk does not read at "
                 "all; it is listed in coverage.skipped with reason `too_large`. It blocks because anything "
                 "could be in it: a script padded past the limit would otherwise pass a gate that blocks it "
                 "whole."),
        why=("An unread file could hold anything, and padding a script past the size limit must not make it "
             "pass."),
        example="A three-megabyte bundled script in a skill, scanned with the default limit.",
        false_positive="A large data file or generated bundle you know to be safe.",
        on_hit=("Raise `--max-file-bytes` to scan it, or leave it out of the target (scan the other paths by "
                "name)."),
    ),
    "coverage.truncated": RuleDoc(
        matches=("A text scanned as a string (`--text`, a frisk-mcp `scan_text` call, a tool description or "
                 "tool result in `frisk proxy`) longer than the size limit (2 MiB characters; "
                 "`--max-file-bytes` for `--text`). Its first and last halves of the limit are "
                 "pattern-matched, with line numbers from the start of the text; the hidden-Unicode check "
                 "reads all of it. The middle is not pattern-matched, so the verdict is never PASS. Standard "
                 "input (`--stdin`) longer than `--max-file-bytes` bytes is pattern-matched only that far: the "
                 "rest is read and dropped, never scanned."),
        why="The middle of an over-long text was not pattern-matched, so the verdict must not be PASS.",
        example="A tool result of several megabytes of text relayed through the proxy.",
        false_positive="A long, legitimate document passed as text.",
        on_hit="Scan the text in smaller parts, or as a file with a larger `--max-file-bytes`.",
    ),
    "coverage.no_servers": RuleDoc(
        matches=("An MCP config (`--mcp-config`, or a config file named as a target) in which frisk found no "
                 "servers. frisk reads `mcpServers` and `servers`, at the top level and in each `projects` "
                 "entry; other formats, such as VS Code's `settings.json` (`mcp.servers`) or Zed's "
                 "`context_servers`, are not read, and neither is a misspelt key such as `mcpservers`. The "
                 "warning names the file and those keys, so a config frisk did not understand is never "
                 "reported clean."),
        why=("A config in which frisk finds no servers was not audited, often because it uses a format frisk "
             "does not read."),
        example="A VS Code settings file whose servers sit under a key frisk does not read.",
        false_positive="A config that really configures no servers, for example an empty `\"mcpServers\": {}`.",
        on_hit=("Check the file is the config your client reads and that its servers sit under one of those "
                "keys; audit a supported config instead."),
    ),
    "fs.symlink_escape": RuleDoc(
        matches=("A symlink in the scanned tree (or a single-file target that is a symlink) whose target, with "
                 "every link resolved, lies outside the scan root. frisk never follows it: the target is not "
                 "opened, so its content cannot reach the excerpts of any report (text, `--json`, `--sarif`, "
                 "frisk-mcp). The finding names the link and its target as the link spells it, with no "
                 "excerpt, and the link is listed in coverage.skipped with reason `symlink_escape`. It is a "
                 "**block** when the target is a credential location under `$HOME` (`.ssh`, `.aws`, `.gnupg`, "
                 "`.config/gcloud`, `.azure`, `.kube`, `.docker/config.json`, `.netrc`), inside one, or a "
                 "directory holding one (such as `$HOME` itself). A symlink to a file inside the root is "
                 "scanned once, at the target's path."),
        why="A link out of the scanned tree can make a tool read, and leak, a file elsewhere on the machine.",
        example=("A skill that ships a link, named like a config file, that points at the user's cloud "
                 "credentials."),
        false_positive=("A repository that links to a shared file elsewhere on the machine, such as a dotfiles "
                        "checkout."),
        on_hit=("Check where the link points and why the content would want it; a planted link to a key or "
                "token file is an exfiltration attempt. Scan the target separately if it should be covered."),
    ),
}
