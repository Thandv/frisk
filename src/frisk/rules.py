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

# --- file classification ----------------------------------------------------

CODE_EXTS = {
    ".py", ".sh", ".bash", ".zsh", ".fish", ".js", ".mjs", ".cjs", ".ts",
    ".rb", ".pl", ".php", ".ps1", ".bat", ".cmd", ".lua", ".r",
}
TEXT_EXTS = {".md", ".markdown", ".txt", ".mdc", ".rst", ".yaml", ".yml", ".json", ".toml"}
SKIP_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz",
    ".tar", ".woff", ".woff2", ".ttf", ".otf", ".mp3", ".mp4", ".wasm", ".so",
    ".dylib", ".pyc",
}

FENCE_RE = re.compile(r"```[^\n]*\n(.*?)```", re.DOTALL)


def _r(p: str) -> re.Pattern:
    return re.compile(p, re.IGNORECASE)


# --- code rules -------------------------------------------------------------

CODE_RULES = [
    # Remote code execution / piped installers
    ("rce.pipe_installer", "rce", "block",
     _r(r"\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(bash|sh|zsh|python[0-9.]*)\b"),
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
     _r(r"\b[A-Z][A-Z0-9_]{2,}(TOKEN|SECRET|API[_-]?KEY|ACCESS[_-]?KEY|PRIVATE[_-]?KEY|PASSWORD)\b"),
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
     _r(r"\brm\s+-[a-z]*r[a-z]*f[a-z]*\s+(/|~|\$HOME|\*)"),
     "recursive force delete of a root/home/glob path"),
    ("destroy.disk", "destructive", "block",
     _r(r"\bdd\s+if=|\bmkfs\b|>\s*/dev/sd|>\s*/dev/disk"),
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
     _r(r"\b(send|post|exfiltrate|upload)\b[^\n]{0,40}\bto\b[^\n]{0,40}https?://"),
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

# Suspicious invisible / control characters used to hide instructions, keyed by
# codepoint (never written literally, so this rule cannot flag its own source).
# Allowed: \t \n \r and a BOM (U+FEFF) only at file start.
SUSPECT_UNICODE = {
    chr(0x200B): "zero-width space",
    chr(0x200C): "zero-width non-joiner",
    chr(0x200D): "zero-width joiner",
    chr(0x200E): "left-to-right mark",
    chr(0x200F): "right-to-left mark",
    chr(0x202A): "left-to-right embedding (bidi)",
    chr(0x202B): "right-to-left embedding (bidi)",
    chr(0x202C): "pop directional formatting (bidi)",
    chr(0x202D): "left-to-right override (bidi)",
    chr(0x202E): "right-to-left override (bidi)",
    chr(0x2060): "word joiner",
    chr(0x2066): "left-to-right isolate (bidi)",
    chr(0x2067): "right-to-left isolate (bidi)",
    chr(0x2068): "first strong isolate (bidi)",
    chr(0x2069): "pop directional isolate (bidi)",
}
_BOM = chr(0xFEFF)

# Map each finding category to the OWASP Top 10 for LLM Applications (2025) entry
# it most directly corresponds to — surfaced in JSON/SARIF output for compliance.
CATEGORY_OWASP = {
    "rce": "LLM03:2025 Supply Chain",
    "exfil": "LLM02:2025 Sensitive Information Disclosure",
    "destructive": "LLM06:2025 Excessive Agency",
    "injection": "LLM01:2025 Prompt Injection",
    "tool-poisoning": "LLM01:2025 Prompt Injection",
    "obfuscation": "LLM01:2025 Prompt Injection",
}


def owasp_for(category: str) -> str:
    return CATEGORY_OWASP.get(category, "")
