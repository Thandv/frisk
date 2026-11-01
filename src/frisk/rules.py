"""Detection rules for the Frisk scanner.

All content is treated as UNTRUSTED. Rules are pure regex matched against text;
nothing here imports, executes, or evaluates scanned content.

Each rule is a tuple: (id, category, severity, compiled_regex, description).
  CODE_RULES run against script files and fenced code blocks in markdown/JSON.
  TEXT_RULES run against the full text of any text/markdown/config file.

Severities:
  block -> must not be installed; fails CI / scan verdict is BLOCK
  warn  -> surfaced for human review; fails CI only with --fail-on warn
"""
from __future__ import annotations

import re
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


# Argument words of one shell command, lazily: no newline or command separator inside.
_ARGS = r"(?:[^\s;&|]+[ \t]+)*?"


# --- code rules -------------------------------------------------------------

CODE_RULES = [
    # Remote code execution / piped installers
    ("rce.pipe_installer", "rce", "block",
     # Piped (lines may continue with a backslash before or after the pipe; the shell may be reached through a path,
     # sudo or env with options), or the download run via process substitution or sh -c.
     _r(r"\b(curl|wget)\b(?:[^\n|]|\\\n)*\|(?:\s|\\\n)*(?:(?:\S*/)?(?:sudo|env)(?:\s+-\S+)*\s+)*"
        r"(?:\S*/)?(bash|sh|zsh|python[0-9.]*)\b"
        r"|\b(?:bash|sh|zsh)\s+(?:<\(|-c\s+[\"']?\$\()\s*(?:curl|wget)\b"),
     "pipe-to-shell remote installer (curl|wget ... | sh)"),
    ("rce.eval_b64", "rce", "block",
     _r(r"(?<![.\w])(eval|exec)\s*\(\s*[^)]*b(ase)?64[._]?decode"),
     "execution of base64-decoded payload"),
    ("rce.python_exec", "rce", "block",
     _r(r"(?<![.\w])exec\s*\(|\bos\.system\s*\(|\bos\.popen\s*\(|(?<![.\w])eval\s*\("),
     "dynamic code/command execution (exec/eval/os.system/os.popen)"),
    ("rce.shell_true", "rce", "block",
     _r(r"\bsubprocess\.(run|call|check_output|check_call|Popen)\s*\([^)]*shell\s*=\s*True"),
     "subprocess with shell=True"),
    ("rce.shell_eval", "rce", "block",
     _r(r"(^|[;&|]\s*)eval\s+[\"$`]"),
     "shell eval of dynamic string"),
    ("rce.pickle", "rce", "block",
     _r(r"\b(pickle|cPickle|marshal)\.loads?\s*\("),
     "deserialization of untrusted data (pickle/marshal)"),
    ("rce.dynamic_import", "rce", "warn",
     _r(r"\b__import__\s*\(|\bimportlib\.import_module\s*\("),
     "dynamic import"),
    # Data exfiltration — secrets
    ("exfil.secret_paths", "exfil", "block",
     _r(r"(~|\$HOME)?/?\.(ssh|aws|gnupg)\b|\.aws/credentials|id_rsa\b"),
     "access to credential/key directories (.ssh/.aws/.gnupg/id_rsa)"),
    ("exfil.dotenv", "exfil", "warn",
     _r(r"\.env(\.|\b)"),
     "access to .env file"),
    # Reading a secret from an env var is NORMAL for any tool that authenticates;
    # it's exfiltration only when paired with egress. Warn, don't block.
    ("exfil.secret_env_read", "exfil", "warn",
     _r(r"(os\.environ|getenv|process\.env|ENV\[|\$\{?)[^\n]{0,30}"
        r"(TOKEN|SECRET|API[_-]?KEY|ACCESS[_-]?KEY|PRIVATE[_-]?KEY|PASSWORD)"),
     "reads a secret-bearing env var (normal for auth; review only with network egress)"),
    ("exfil.secret_name", "exfil", "warn",
     # Case-sensitive: SCREAMING_CASE names only, not ordinary identifiers like access_token.
     re.compile(r"\b[A-Z][A-Z0-9_]{2,}(TOKEN|SECRET|API[_-]?KEY|ACCESS[_-]?KEY|PRIVATE[_-]?KEY|PASSWORD)\b"),
     "mention of a secret-bearing identifier"),
    ("exfil.keychain_read", "exfil", "block",
     _r(r"\bsecurity\s+find-(generic|internet)-password\b"),
     "macOS keychain password read (security find-*-password)"),
    ("exfil.keychain_mention", "exfil", "warn",
     _r(r"\bkeychain\b|\bsecurity\s+list-keychains\b"),
     "keychain reference (non-secret-reading)"),
    # Data exfiltration — network from a script
    ("exfil.net_lib", "exfil", "warn",
     _r(r"\b(requests|urllib|urllib2|httplib|http\.client|aiohttp|httpx)\b"),
     "network library use inside a script"),
    ("exfil.net_tool", "exfil", "warn",
     _r(r"(^|[;&|`$(\s])(nc|netcat|telnet|scp|sftp|rsync)\s"),
     "network/transfer tool use inside a script"),
    # Destructive operations
    ("destroy.rm_rf", "destructive", "block",
     # Recursive and force in any spelling (-rf, -fr, -r -f, --recursive --force); the target
     # is the root, a top-level system directory, the home directory or a credential
     # directory in it, or a glob over one of them or the current directory, optionally
     # quoted. Paths below those, such as temp and build directories, do not match.
     _r(r"\brm\s+(?=" + _ARGS + r"(?:-[a-z]*r|--recursive\b))(?=" + _ARGS + r"(?:-[a-z]*f|--force\b))"
        + _ARGS + r"[\"']?(?:(?:~|\$HOME|\$\{HOME\})[\"']?(?:/[\"']?\.(?:ssh|aws|gnupg|config|kube|docker))?"
        r"|/(?:etc|usr|bin|sbin|var|System|Library|opt|private|home|Users|root)?|\*)"
        r"[\"']?(?:/?\*|/)?[\"']?(?=[\s;&|)]|$)"),
     "recursive force delete of a root, system, home or credential directory"),
    ("destroy.disk", "destructive", "block",
     # dd writing to a device (not the null/zero/stdio sinks), mkfs on a device, or a
     # redirect into a raw disk. dd to a regular file does not match.
     _r(r"\bdd\b[^\n;&|]*\bof=[\"']?/dev/(?!(?:null|zero|stdout|stderr)\b|fd/)"
        r"|\bmkfs(?:\.\w+)?\b[^\n;&|]*\s[\"']?/dev/|>\s*/dev/sd|>\s*/dev/disk"),
     "raw disk write / format"),
    ("destroy.forkbomb", "destructive", "block",
     _r(r":\(\)\s*\{\s*:\|:&\s*\}\s*;:"),
     "fork bomb"),
    ("destroy.chmod_777", "destructive", "warn",
     _r(r"\bchmod\s+(-R\s+)?0?777\b"),
     "world-writable chmod 777"),
]

# --- text rules (prose, markdown, JSON tool descriptions, config) -----------

TEXT_RULES = [
    ("inject.ignore_prev", "injection", "block",
     _r(r"\bignore\s+(all\s+|the\s+)?(previous|prior|above|preceding)\s+(instructions|prompts?|context)"),
     "prompt-injection: 'ignore previous instructions'"),
    ("inject.disregard", "injection", "block",
     _r(r"\bdisregard\s+(all\s+|the\s+)?(previous|prior|above|system)\b"),
     "prompt-injection: 'disregard the above/system'"),
    ("inject.fake_tool", "injection", "warn",
     _r(r"<\s*(function_calls|tool_call|invoke|antml:)"),
     "embedded fake tool-call / function-call markup"),
    ("inject.role_override", "injection", "warn",
     _r(r"<\|im_start\|>\s*system|<\|system\|>"),
     "embedded chat-template system role override"),
    ("inject.exfil_instr", "injection", "warn",
     # Any inflection of the verb; at most one newline in the match, so never a blank line.
     _r(r"\b(sends?|sending|sent|posts?|posted|posting|exfiltrat(?:e|es|ed|ing)|uploads?|uploaded|uploading)\b"
        r"(?:(?:[^\n]{0,40}\n)?[^\n]{0,40}\bto\b[^\n]{0,40}|[^\n]{0,40}\bto\b(?:[^\n]{0,40}\n)?[^\n]{0,40})"
        r"https?://"),
     "instruction to send data to an external URL"),
    # --- MCP tool-poisoning patterns (hidden directives in tool descriptions) ---
    ("inject.hide_from_user", "tool-poisoning", "block",
     _r(r"\bdo\s+not\s+(tell|inform|mention|reveal|notify|show)\b[^\n]{0,30}\b(the\s+)?user\b"),
     "tool-poisoning: instruction to hide an action from the user"),
    ("inject.hidden_important", "tool-poisoning", "warn",
     _r(r"<\s*important\s*>|<\s*secret\s*>|<\s*system[_-]?note\s*>"),
     "tool-poisoning: hidden <IMPORTANT>/<SECRET> directive block in description"),
    ("inject.before_using", "tool-poisoning", "warn",
     _r(r"\bbefore\s+(using|calling|invoking|you\s+use)\b[^\n]{0,40}\b(tool|function|this)\b"),
     "tool-poisoning: side-effect instruction prefixed to a tool description"),
    ("inject.read_then_send", "tool-poisoning", "warn",
     _r(r"\b(read|cat|open)\b[^\n]{0,40}\b(\.ssh|\.aws|\.env\b|id_rsa|credentials)\b"),
     "tool-poisoning: instruction to read sensitive files"),
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

INSTRUCTION_RULES = [
    ("inject.sensitive_path_instruction", "injection", "block",
     re.compile(_UNNEGATED_CLAUSE + r"\b(?:copy|send|upload|read|cat|include|attach|print)\b" + _SAME_SENTENCE
                + _CREDENTIAL_LOCATION, re.IGNORECASE | re.MULTILINE),
     "instruction to the agent to copy, read or send a credential file"),
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
    **{rid: (cat, sev, desc) for rid, cat, sev, _rx, desc in CODE_RULES + TEXT_RULES + INSTRUCTION_RULES},
    **{rid: (cat, sev, desc) for rid, cat, sev, desc in UNICODE_RULES},
    **{rid: (cat, sev, desc) for rid, cat, sev, desc in COVERAGE_RULES},
}
