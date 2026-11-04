"""Detection rules for the Frisk scanner.

All content is treated as UNTRUSTED. Rules are regular expressions matched against
text; nothing here imports, executes, or evaluates scanned content.

Each rule is a tuple: (id, category, severity, pattern, description, contexts), where the
pattern is a compiled regex or, for destroy.rm_rf, a PerCommand (one match per shell
command), and contexts names the engine.scan_text contexts (CONTEXTS) the rule runs in.
  CODE_RULES run against script files and fenced code blocks in markdown/JSON.
  TEXT_RULES run against the full text of any text/markdown/config file.
  INSTRUCTION_RULES run against agent-instruction files.
  PROSE_RULES run in scan_text only, in the contexts they name.
Files are scanned by these lists, whatever a rule's contexts.

Every pattern scans in linear time: each window between a rule's start and what it must
find is bounded, and where a window could hold another start of the same rule (so that a
run of starts would rescan it from each), the window stops there and the later start, which
sees the same rest of the line, matches instead. tests/test_perf.py times each rule on
1 MiB of adversarial text.

Severities:
  block -> must not be installed; fails CI / scan verdict is BLOCK
  warn  -> surfaced for human review; fails CI only with --fail-on warn
"""
from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

# --- file classification ----------------------------------------------------

CODE_EXTS = {
    ".py", ".sh", ".bash", ".zsh", ".ksh", ".fish", ".command", ".js", ".mjs", ".cjs", ".jsx",
    ".ts", ".mts", ".cts", ".tsx", ".rb", ".pl", ".php", ".ps1", ".psm1", ".bat", ".cmd",
    ".vbs", ".applescript", ".lua", ".r",
}
TEXT_EXTS = {
    ".md", ".markdown", ".txt", ".mdc", ".rst", ".yaml", ".yml", ".json", ".toml",
    ".html", ".htm", ".xml", ".svg", ".cfg", ".ini", ".conf",
}
# Markdown: the markdown surface finds their code and hidden regions.
MARKDOWN_EXTS = {".md", ".markdown", ".mdc"}
# Media: never read, no finding, counted in coverage.skipped as "binary".
MEDIA_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".pdf", ".woff",
    ".woff2", ".ttf", ".otf", ".mp3", ".mp4", ".wav", ".mov",
}
# Executable or archive content frisk cannot scan as text: a coverage.binary warning.
EXECUTABLE_EXTS = {
    ".so", ".dylib", ".dll", ".wasm", ".exe", ".node", ".pyc", ".pyo", ".jar", ".class",
}
ARCHIVE_EXTS = {".zip", ".tar", ".gz", ".tgz"}
# Opaque data formats: when not valid UTF-8 they are skipped silently (counted as binary).
OPAQUE_DATA_EXTS = {".bin", ".dat", ".db", ".sqlite", ".sqlite3", ".npy", ".parquet"}
# Leading bytes of native executables. Checked only for a file that is not valid UTF-8 and
# has no code/text extension or shebang (see engine._read_text).
EXECUTABLE_MAGIC = {
    b"\x7fELF": "ELF",
    b"\xfe\xed\xfa\xce": "Mach-O",
    b"\xfe\xed\xfa\xcf": "Mach-O",
    b"\xce\xfa\xed\xfe": "Mach-O",
    b"\xcf\xfa\xed\xfe": "Mach-O",
    b"\xca\xfe\xba\xbe": "Mach-O universal or Java class",
}


def is_code(path: Path, text: str) -> bool:
    """A script: a code extension, or a first line that is a shebang, whatever the extension."""
    return path.suffix.lower() in CODE_EXTS or text.startswith("#!")


def executable_magic(data: bytes) -> str | None:
    """The executable format named by the file's first four bytes, if any."""
    return EXECUTABLE_MAGIC.get(data[:4])



def _r(p: str) -> re.Pattern:
    return re.compile(p, re.IGNORECASE)


def _not_at(start: str, first: str, excluded: str) -> str:
    """One character of a rule's window, other than `excluded`, at which `start` (another
    start of the same rule) does not begin. `first` lists every character `start` can begin
    with, so any other character is taken in one step."""
    return rf"(?:[^{excluded}{first}]|(?!{start})[{first}])"


class PerCommand:
    """destroy.rm_rf's pattern: it matches once at the first rm word of each shell command,
    then consumes the next _RM_SKIP argument words, so the rm words among them are not
    started from again: a command of many rm words is read in linear time. Only a match
    whose 'hit' group took part is a finding. A skipped rm word's own window (up to 32 words
    after it) lies inside the first one's (up to _RM_WINDOW words), so it finds nothing the
    first did not."""

    def __init__(self, pattern: str) -> None:
        self._rx = re.compile(pattern, re.IGNORECASE)

    def finditer(self, text: str) -> Iterator[re.Match[str]]:
        return (m for m in self._rx.finditer(text) if m.group("hit") is not None)

    def search(self, text: str) -> re.Match[str] | None:
        return next(self.finditer(text), None)


# Argument words of one shell command: no newline or command separator inside. An rm word's
# flags and target are looked for in its next _RM_WINDOW words; the next _RM_SKIP are then
# consumed, so the window of any rm word among them (32 words, as before) lies inside this one.
_RM_WINDOW, _RM_SKIP = 256, 224
_ARGS = rf"(?:[^\s;&|]+[ \t]+){{0,{_RM_WINDOW}}}?"
_RM_TARGET = (r"[\"']?(?:(?:~|\$HOME|\$\{HOME\})[\"']?(?:/[\"']?\.(?:ssh|aws|gnupg|config|kube|docker))?"
              r"|/(?:etc|usr|bin|sbin|var|System|Library|opt|private|home|Users|root)?|\*)"
              r"[\"']?(?:/?\*|/)?[\"']?(?=[\s;&|)]|$)")


# --- scan_text contexts ------------------------------------------------------

# "default": every code and text rule (--text, frisk-mcp). The frisk proxy's: "tool_description"
# (the text rules, the commands that harm when an agent runs them, instructions to read or
# send a credential file, and a private key or credential file named at all; a credential
# directory or config file named in prose only warns) and "tool_result" (the injection and
# tool-poisoning rules, those instructions and those commands, but no other code rule: a
# result may hold code, such as a file that calls eval). The hidden-Unicode check runs in all three.
CONTEXTS = ("default", "tool_description", "tool_result")
_EVERY = frozenset(CONTEXTS)
_DEFAULT = frozenset({"default"})
_NOT_DEFAULT = frozenset({"tool_description", "tool_result"})
_DESCRIPTION = frozenset({"tool_description"})

_SECRET_PATHS = _r(r"(~|\$HOME)?/?\.(ssh|aws|gnupg)\b|\.aws/credentials|id_rsa\b")

Rule = tuple[str, str, str, "re.Pattern[str] | PerCommand", str, frozenset[str]]

# --- code rules -------------------------------------------------------------

CODE_RULES: list[Rule] = [
    # Remote code execution / piped installers
    ("rce.pipe_installer", "rce", "block",
     # Piped (lines may continue with a backslash before or after the pipe; the shell may be
     # named by a path, or reached through sudo or env with options), or the download run via
     # process substitution or sh -c.
     # A run never crosses another curl/wget (that one matches the same pipe), so it is linear.
     _r(r"\b(curl|wget)\b(?:(?!\b(?:curl|wget)\b)[^\n|]|\\\n)*\|(?:\s|\\\n)*(?:(?:\S*/)?(?:sudo|env)(?:\s+-\S+)*\s+)*"
        r"(?:\S*/)?(bash|sh|zsh|python[0-9.]*)\b"
        r"|\b(?:bash|sh|zsh)\s+(?:<\(|-c\s+[\"']?\$\()\s*(?:curl|wget)\b"),
     "pipe-to-shell remote installer (curl|wget ... | sh)", _EVERY),
    ("rce.eval_b64", "rce", "block",
     # Within 400 characters of the same parentheses, whitespace included (a separate \s*
     # before the window would try the window from every point of a whitespace run); the
     # window stops at another eval( or exec(, which then matches the same decode.
     _r(r"(?<![.\w])(eval|exec)\s*\(" + _not_at(r"(?<![.\w])(?:eval|exec)\s*\(", "e", ")") + "{0,400}"
        r"b(ase)?64[._]?decode"),
     "execution of base64-decoded payload", _DEFAULT),
    ("rce.python_exec", "rce", "block",
     _r(r"(?<![.\w])exec\s*\(|\bos\.system\s*\(|\bos\.popen\s*\(|(?<![.\w])eval\s*\("),
     "dynamic code/command execution (exec/eval/os.system/os.popen)", _DEFAULT),
    ("rce.shell_true", "rce", "block",
     # Within 400 characters of the same call; the window stops at another subprocess call,
     # which then matches the same shell=True.
     _r(r"\bsubprocess\.(run|call|check_output|check_call|Popen)\s*\("
        + _not_at(r"\bsubprocess\.(?:run|call|check_output|check_call|Popen)\s*\(", "s", ")") + "{0,400}"
        r"shell\s*=\s*True"),
     "subprocess with shell=True", _DEFAULT),
    ("rce.shell_eval", "rce", "block",
     _r(r"(^|[;&|]\s*)eval\s+[\"$`]"),
     "shell eval of dynamic string", _DEFAULT),
    ("rce.pickle", "rce", "block",
     _r(r"\b(pickle|cPickle|marshal)\.loads?\s*\("),
     "deserialization of untrusted data (pickle/marshal)", _DEFAULT),
    ("rce.dynamic_import", "rce", "warn",
     _r(r"\b__import__\s*\(|\bimportlib\.import_module\s*\("),
     "dynamic import", _DEFAULT),
    # Data exfiltration — secrets
    ("exfil.secret_paths", "exfil", "block", _SECRET_PATHS,
     "access to credential/key directories (.ssh/.aws/.gnupg/id_rsa)", _DEFAULT),
    ("exfil.dotenv", "exfil", "warn",
     _r(r"\.env(\.|\b)"),
     "access to .env file", _DEFAULT),
    # Reading a secret from an env var is NORMAL for any tool that authenticates;
    # it's exfiltration only when paired with egress. Warn, don't block.
    ("exfil.secret_env_read", "exfil", "warn",
     # Up to 30 characters on the line; the window stops at a '$', which then matches the
     # same name. The lookahead skips positions where no name can begin.
     _r(r"(os\.environ|getenv|process\.env|ENV\[|\$\{?)[^\n$]{0,30}(?=[tsap])"
        r"(TOKEN|SECRET|API[_-]?KEY|ACCESS[_-]?KEY|PRIVATE[_-]?KEY|PASSWORD)"),
     "reads a secret-bearing env var (normal for auth; review only with network egress)", _DEFAULT),
    ("exfil.secret_name", "exfil", "warn",
     # Case-sensitive: SCREAMING_CASE names only, not ordinary identifiers like access_token.
     re.compile(r"\b[A-Z][A-Z0-9_]{2,}(TOKEN|SECRET|API[_-]?KEY|ACCESS[_-]?KEY|PRIVATE[_-]?KEY|PASSWORD)\b"),
     "mention of a secret-bearing identifier", _DEFAULT),
    ("exfil.keychain_read", "exfil", "block",
     _r(r"\bsecurity\s+find-(generic|internet)-password\b"),
     "macOS keychain password read (security find-*-password)", _EVERY),
    ("exfil.keychain_mention", "exfil", "warn",
     _r(r"\bkeychain\b|\bsecurity\s+list-keychains\b"),
     "keychain reference (non-secret-reading)", _DEFAULT),
    # Data exfiltration — network from a script
    ("exfil.net_lib", "exfil", "warn",
     _r(r"\b(requests|urllib|urllib2|httplib|http\.client|aiohttp|httpx)\b"),
     "network library use inside a script", _DEFAULT),
    ("exfil.net_tool", "exfil", "warn",
     _r(r"(^|[;&|`$(\s])(nc|netcat|telnet|scp|sftp|rsync)\s"),
     "network/transfer tool use inside a script", _DEFAULT),
    # Destructive operations
    ("destroy.rm_rf", "destructive", "block",
     # Recursive and force in any spelling (-rf, -fr, -r -f, --recursive --force); the target
     # is the root, a top-level system directory, the home directory or a credential
     # directory in it, or a glob over one of them or the current directory, optionally
     # quoted. Paths below those, such as temp and build directories, do not match.
     PerCommand(r"\brm\s+(?P<hit>(?=" + _ARGS + r"(?:-[a-z]*r|--recursive\b))(?=" + _ARGS + r"(?:-[a-z]*f|--force\b))"
                r"(?=" + _ARGS + _RM_TARGET + r"))?" + rf"(?:[^\s;&|]+[ \t]+){{0,{_RM_SKIP}}}"),
     "recursive force delete of a root, system, home or credential directory", _EVERY),
    ("destroy.disk", "destructive", "block",
     # dd writing to a device (not the null/zero/stdio sinks), mkfs on a device, or a
     # redirect into a raw disk. dd to a regular file does not match. A run never crosses
     # another dd/mkfs (that one reaches the same target), so the scan stays linear.
     _r(r"\bdd\b(?:(?!\bdd\b)[^\n;&|])*\bof=[\"']?/dev/(?!(?:null|zero|stdout|stderr)\b|fd/)"
        r"|\bmkfs(?:\.\w+)?\b(?:(?!\bmkfs(?:\.\w+)?\b)[^\n;&|])*\s[\"']?/dev/|>\s*/dev/sd|>\s*/dev/disk"),
     "raw disk write / format", _EVERY),
    ("destroy.forkbomb", "destructive", "block",
     _r(r":\(\)\s*\{\s*:\|:&\s*\}\s*;:"),
     "fork bomb", _EVERY),
    ("destroy.chmod_777", "destructive", "warn",
     _r(r"\bchmod\s+(-R\s+)?0?777\b"),
     "world-writable chmod 777", _DEFAULT),
]

# --- text rules (prose, markdown, JSON tool descriptions, config) -----------

_EXFIL_VERBS = r"sends?|sending|sent|posts?|posted|posting|exfiltrat(?:e|es|ed|ing)|uploads?|uploaded|uploading"
_BEFORE_TO = _not_at(r"\b(?:" + _EXFIL_VERBS + r")\b", "speu", r"\n")

TEXT_RULES: list[Rule] = [
    ("inject.ignore_prev", "injection", "block",
     _r(r"\bignore\s+(all\s+|the\s+)?(previous|prior|above|preceding)\s+(instructions|prompts?|context)"),
     "prompt-injection: 'ignore previous instructions'", _EVERY),
    ("inject.disregard", "injection", "block",
     _r(r"\bdisregard\s+(all\s+|the\s+)?(previous|prior|above|system)\b"),
     "prompt-injection: 'disregard the above/system'", _EVERY),
    ("inject.fake_tool", "injection", "warn",
     _r(r"<\s*(function_calls|tool_call|invoke|antml:)"),
     "embedded fake tool-call / function-call markup", _EVERY),
    ("inject.role_override", "injection", "warn",
     _r(r"<\|im_start\|>\s*system|<\|system\|>"),
     "embedded chat-template system role override", _EVERY),
    ("inject.exfil_instr", "injection", "warn",
     # Any inflection of the verb; at most one newline in the match, so never a blank line.
     # The text just before 'to', on its line, stops at another of these verbs, which then
     # matches with the same 'to' and URL. The URL is found from its ':' (a literal the scan
     # jumps to), so up to 40 characters may come before 'https' and, one more, 41 before 'http'.
     _r(r"\b(" + _EXFIL_VERBS + r")\b(?:" + _BEFORE_TO + r"{0,40}\bto\b(?:[^\n]{0,40}\n)?[^\n]{0,45}"
        r"|[^\n]{0,40}\n" + _BEFORE_TO + r"{0,40}\bto\b[^\n]{0,45})"
        r":(?:(?<=https:)|(?<=http:))//"),
     "instruction to send data to an external URL", _EVERY),
    # --- MCP tool-poisoning patterns (hidden directives in tool descriptions) ---
    ("inject.hide_from_user", "tool-poisoning", "block",
     _r(r"\bdo\s+not\s+(tell|inform|mention|reveal|notify|show)\b[^\n]{0,30}\b(the\s+)?user\b"),
     "tool-poisoning: instruction to hide an action from the user", _EVERY),
    ("inject.hidden_important", "tool-poisoning", "warn",
     _r(r"<\s*important\s*>|<\s*secret\s*>|<\s*system[_-]?note\s*>"),
     "tool-poisoning: hidden <IMPORTANT>/<SECRET> directive block in description", _EVERY),
    ("inject.before_using", "tool-poisoning", "warn",
     _r(r"\bbefore\s+(using|calling|invoking|you\s+use)\b[^\n]{0,40}\b(tool|function|this)\b"),
     "tool-poisoning: side-effect instruction prefixed to a tool description", _EVERY),
    ("inject.read_then_send", "tool-poisoning", "warn",
     # Up to 40 characters on the line; the window stops at another read/cat/open, which
     # then matches the same file.
     _r(r"\b(read|cat|open)\b" + _not_at(r"\b(?:read|cat|open)\b", "rco", r"\n") + "{0,40}"
        r"\b(\.ssh|\.aws|\.env\b|id_rsa|credentials)\b"),
     "tool-poisoning: instruction to read sensitive files", _EVERY),
]

# --- instruction rules (agent-instruction files only: see surfaces/instructions.py) ------

# A file or store that holds credentials. Public keys and ssh config are not credentials.
_CREDENTIAL_LOCATION = (
    r"(?:\.ssh\b(?!/(?:[\w.-]+\.pub|config|known_hosts)\b)|\bid_(?:rsa|dsa|ecdsa|ed25519)\b(?!\.pub)"
    r"|\.aws/credentials\b|\.config/gcloud\b|\.azure/|\.gnupg\b|\bprivate[ _-]?keys?\b|\bkeychain\b)")
# Text from the start of a line or clause up to the verb, with no negation in it, so a
# defensive "never read ~/.ssh" does not match.
_UNNEGATED_CLAUSE = r"(?:^|(?<=[.!?;:]))(?:(?!\b(?:never|not|no|avoid)\b|n['\u2019]t\b)[^\n.!?;:])*?"
# From the verb to the location: up to 60 characters in the same sentence (a '.', '!', '?' or
# ';' inside a path such as ~/.ssh is not a sentence end), so the verb of one sentence never
# reaches the location of the next, which may be a defensive "never read ~/.ssh".
_SAME_SENTENCE = r"(?:[^\n.!?;]|[.!?;](?=\S)){0,60}?"

INSTRUCTION_RULES: list[Rule] = [
    ("inject.sensitive_path_instruction", "injection", "block",
     re.compile(_UNNEGATED_CLAUSE + r"\b(?:copy|send|upload|read|cat|include|attach|print)\b" + _SAME_SENTENCE
                + _CREDENTIAL_LOCATION, re.IGNORECASE | re.MULTILINE),
     "instruction to the agent to copy, read or send a credential file", _NOT_DEFAULT),
]

# --- prose rules (scan_text only: see CONTEXTS) ------------------------------------

PROSE_RULES: list[Rule] = [
    # exfil.secret_paths' pattern, at warn: a tool that says it reads ~/.ssh/config names a
    # path; an instruction to read or send a key is inject.sensitive_path_instruction (block).
    ("exfil.secret_paths_prose", "exfil", "warn", _SECRET_PATHS,
     "names a credential/key directory (.ssh/.aws/.gnupg/id_rsa) in a tool description", _DESCRIPTION),
    # A private key or credential file: a description has no harmless reason to name one, and
    # how it asks for it (any verb, a negation word) must not matter. Public keys do not match.
    ("exfil.secret_files_prose", "exfil", "block",
     _r(r"\bid_(?:rsa|dsa|ecdsa|ed25519)\b(?!\.pub)|\.aws/credentials\b|\.gnupg\b"),
     "names a private key or credential file (id_rsa/id_ed25519, .aws/credentials, .gnupg) in a tool description",
     _DESCRIPTION),
]

# Suspicious invisible / control characters used to hide instructions:
# (first codepoint, last codepoint, name, severity). Codepoints are never written
# literally, so these rules cannot flag their own source. Not listed, so never
# reported: \t \n \r. hidden_unicode() applies the exceptions noted per entry.
SUSPECT_UNICODE = [
    (0x200B, 0x200B, "zero-width space", "block"),
    (0x200C, 0x200C, "zero-width non-joiner", "block"),
    (0x200D, 0x200D, "zero-width joiner", "block"),  # allowed directly between two emoji
    (0x200E, 0x200E, "left-to-right mark", "block"),
    (0x200F, 0x200F, "right-to-left mark", "block"),
    (0x202A, 0x202A, "left-to-right embedding (bidi)", "block"),
    (0x202B, 0x202B, "right-to-left embedding (bidi)", "block"),
    (0x202C, 0x202C, "pop directional formatting (bidi)", "block"),
    (0x202D, 0x202D, "left-to-right override (bidi)", "block"),
    (0x202E, 0x202E, "right-to-left override (bidi)", "block"),
    (0x2060, 0x2060, "word joiner", "block"),
    (0x2066, 0x2066, "left-to-right isolate (bidi)", "block"),
    (0x2067, 0x2067, "right-to-left isolate (bidi)", "block"),
    (0x2068, 0x2068, "first strong isolate (bidi)", "block"),
    (0x2069, 0x2069, "pop directional isolate (bidi)", "block"),
    (0xE0000, 0xE007F, "tag characters", "block"),  # allowed as a subdivision-flag sequence
    (0xE0100, 0xE01EF, "run of supplementary variation selectors", "warn"),  # 2 or more in a row
    (0x2061, 0x2064, "invisible operator", "warn"),
    (0x00AD, 0x00AD, "soft hyphen", "warn"),
    (0x180E, 0x180E, "Mongolian vowel separator", "warn"),
    (0xFEFF, 0xFEFF, "byte-order mark after the start of the text", "warn"),  # allowed at offset 0
]

# The hidden-Unicode rules, one per severity: (id, category, severity, description).
# Their matcher is hidden_unicode().
UNICODE_RULES = [
    ("unicode.invisible", "obfuscation", "block", "suspicious invisible/bidi character"),
    ("unicode.hidden_format", "obfuscation", "warn", "hidden formatting character"),
]

# Coverage rules: content frisk could not pattern-match. (id, category, severity, description)
COVERAGE_RULES = [
    ("coverage.binary", "coverage", "warn",
     "executable or archive content that cannot be scanned as text"),
    ("coverage.unreadable", "coverage", "warn",
     "file that could not be read or is not valid UTF-8, or a directory that could not be listed"),
    ("coverage.nested_vcs", "coverage", "warn",
     "a .git directory below the top of the target, whose contents are not scanned"),
    ("coverage.surface_error", "coverage", "warn",
     "a scan surface failed on a file, so part of it may not have been pattern-matched"),
    ("coverage.unscanned", "coverage", "warn",
     "content frisk did not scan: an MCP server (remote, a package not in the local cache, or no "
     "source found), or the rest of a tree after a scan limit was hit"),
    ("coverage.too_large", "coverage", "block",
     "a file over the size limit, not read: it fails the scan, since anything could be in it"),
    ("coverage.truncated", "coverage", "warn",
     "text over the size limit: only part of it was pattern-matched (the first and last parts of a string, "
     "the first part of standard input)"),
    ("coverage.no_servers", "coverage", "warn",
     "an MCP config in which frisk found no servers, so nothing in it was audited"),
    ("fs.symlink_escape", "exfil", "warn",
     "a symlink whose target lies outside the scanned tree, not read (block when it points at a credential "
     "location)"),
]


def _suspect_class(lo: int, hi: int) -> str:
    return re.escape(chr(lo)) + ("" if lo == hi else "-" + re.escape(chr(hi)))


# Any suspect character, as one class so the scan stays fast.
_SUSPECT_RE = re.compile("[" + "".join(_suspect_class(lo, hi) for lo, hi, _n, _s in SUSPECT_UNICODE) + "]")
_ENTRY_OF = {cp: i for i, (lo, hi, _n, _s) in enumerate(SUSPECT_UNICODE) for cp in range(lo, hi + 1)}
_RUN_ENTRIES = (0xE0000, 0xE0100)  # tag characters and variation selectors are judged as runs
# The tag runs of the three recommended (RGI) subdivision flags: England, Scotland, Wales.
# Any other run, even one shaped like a subdivision id, can spell hidden text a few letters
# per black flag, so it blocks.
_FLAG_TAGS = re.compile("|".join(
    re.escape("".join(chr(0xE0000 + ord(c)) for c in sub) + chr(0xE007F)) for sub in ("gbeng", "gbsct", "gbwls")))
_BLACK_FLAG = chr(0x1F3F4)


def _is_emoji(ch: str) -> bool:
    """Pictographic symbol ranges (BMP symbols and the supplementary emoji blocks)."""
    return 0x2300 <= ord(ch) <= 0x2BFF or 0x1F000 <= ord(ch) <= 0x1FAFF


def _allowed(text: str, start: int, end: int, lo: int, starts_text: bool) -> bool:
    """The legitimate uses of a suspect character, run or sequence at text[start:end]."""
    if lo == 0x200D:  # emoji ZWJ sequence; the left emoji may carry VS-16 (U+FE0F)
        left = text[start - 1:start]
        if left == chr(0xFE0F):
            left = text[start - 2:start - 1]
        return bool(left) and _is_emoji(left) and end < len(text) and _is_emoji(text[end])
    if lo == 0xE0000:  # subdivision flag: black flag, tag letters/digits, cancel tag
        return text[start - 1:start] == _BLACK_FLAG and _FLAG_TAGS.fullmatch(text, start, end) is not None
    if lo == 0xE0100:
        return end - start < 2
    if lo == 0xFEFF:
        return start == 0 and starts_text
    return False


def hidden_unicode(text: str, starts_text: bool = True) -> list[tuple[int, str, str]]:
    """Return (offset, rule id, description) for the first reportable use of each suspect entry.

    Offsets index into `text`. `starts_text` says whether `text` begins the file or input,
    where a BOM is encoding, not content (files are decoded with utf-8-sig, which already
    drops a leading one).
    """
    rule_for = {sev: (rid, desc) for rid, _cat, sev, desc in UNICODE_RULES}
    hits: dict[int, tuple[int, str, str]] = {}
    m = _SUSPECT_RE.search(text)
    while m is not None:
        start = m.start()
        i = _ENTRY_OF[ord(m.group())]
        lo, hi, name, sev = SUSPECT_UNICODE[i]
        end = start + 1
        while lo in _RUN_ENTRIES and end < len(text) and lo <= ord(text[end]) <= hi:
            end += 1
        if i not in hits and not _allowed(text, start, end, lo, starts_text):
            rid, desc = rule_for[sev]
            hits[i] = (start, rid, f"{desc}: {name}")
        m = _SUSPECT_RE.search(text, end)
    return list(hits.values())

# Map each finding category to the OWASP Top 10 for LLM Applications (2025) entry
# it most directly corresponds to — surfaced in JSON/SARIF output for compliance.
CATEGORY_OWASP = {
    "rce": "LLM03:2025 Supply Chain",
    "exfil": "LLM02:2025 Sensitive Information Disclosure",
    "destructive": "LLM06:2025 Excessive Agency",
    "injection": "LLM01:2025 Prompt Injection",
    "tool-poisoning": "LLM01:2025 Prompt Injection",
    "obfuscation": "LLM01:2025 Prompt Injection",
    "coverage": "LLM03:2025 Supply Chain",
}


def owasp_for(category: str) -> str:
    return CATEGORY_OWASP.get(category, "")


# Every rule id frisk can report -> (category, severity, description). docs/rules.md has
# one section per id (tests/test_rules_doc.py keeps them in step).
RULE_META: dict[str, tuple[str, str, str]] = {
    **{rid: (cat, sev, desc) for rid, cat, sev, _rx, desc, _ctx in CODE_RULES + TEXT_RULES + INSTRUCTION_RULES
       + PROSE_RULES},
    **{rid: (cat, sev, desc) for rid, cat, sev, desc in UNICODE_RULES},
    **{rid: (cat, sev, desc) for rid, cat, sev, desc in COVERAGE_RULES},
}
