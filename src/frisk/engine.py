"""Static scan engine. Zero-execution: reads bytes, matches regex, returns findings."""
from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path

from .rules import (
    CODE_EXTS, SKIP_EXTS, FENCE_RE, CODE_RULES, TEXT_RULES, SUSPECT_UNICODE, _BOM,
)

SEVERITY_ORDER = {None: 0, "warn": 1, "block": 2}


@dataclass
class Finding:
    path: str
    line: int
    rule: str
    category: str
    severity: str
    description: str
    excerpt: str

    def as_dict(self) -> dict:
        return asdict(self)


def _line_of(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


def _excerpt(text: str, idx: int, span: int = 80) -> str:
    start = max(0, idx - 10)
    snippet = text[start:idx + span].replace("\n", "\\n")
    return snippet.strip()[:120]


def _scan_code(text: str, rel: str, out: list[Finding]) -> None:
    for rid, cat, sev, rx, desc in CODE_RULES:
        for m in rx.finditer(text):
            out.append(Finding(rel, _line_of(text, m.start()), rid, cat, sev,
                               desc, _excerpt(text, m.start())))


def _scan_text(text: str, rel: str, out: list[Finding]) -> None:
    for rid, cat, sev, rx, desc in TEXT_RULES:
        for m in rx.finditer(text):
            out.append(Finding(rel, _line_of(text, m.start()), rid, cat, sev,
                               desc, _excerpt(text, m.start())))
    body = text[1:] if text[:1] == _BOM else text
    for ch, name in SUSPECT_UNICODE.items():
        idx = body.find(ch)
        if idx != -1:
            out.append(Finding(rel, _line_of(body, idx), "unicode.invisible",
                               "obfuscation", "block",
                               f"suspicious invisible/bidi character: {name}", ""))


def scan_text(text: str, label: str = "<text>") -> list[Finding]:
    """Scan a raw string as both code and prose (used by the MCP server / --text)."""
    out: list[Finding] = []
    _scan_code(text, label, out)
    _scan_text(text, label, out)
    return out


def scan_file(path: Path, root: Path | None = None) -> list[Finding]:
    rel = str(path.relative_to(root)) if root else str(path)
    ext = path.suffix.lower()
    if ext in SKIP_EXTS:
        return []
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return []  # binary or unreadable -> not pattern-scannable
    out: list[Finding] = []
    if ext in CODE_EXTS:
        _scan_code(text, rel, out)
        _scan_text(text, rel, out)
    else:
        _scan_text(text, rel, out)
        for m in FENCE_RE.finditer(text):
            _scan_code(m.group(1), rel, out)
    return out


def scan_path(path: str | Path, root: Path | None = None) -> list[Finding]:
    p = Path(path)
    if p.is_file():
        return scan_file(p, root or p.parent)
    out: list[Finding] = []
    base = root or p
    for f in sorted(p.rglob("*")):
        if f.is_file() and ".git" not in f.parts:
            out.extend(scan_file(f, base))
    return out


def worst_severity(findings: list[Finding]) -> str | None:
    sevs = {f.severity for f in findings}
    if "block" in sevs:
        return "block"
    if "warn" in sevs:
        return "warn"
    return None


def verdict(findings: list[Finding]) -> str:
    """High-level verdict for humans/agents: PASS | WARN | BLOCK."""
    return {None: "PASS", "warn": "WARN", "block": "BLOCK"}[worst_severity(findings)]


def fails(findings: list[Finding], fail_on: str = "block") -> bool:
    """Whether this scan should fail a gate, given a threshold (block | warn)."""
    return SEVERITY_ORDER[worst_severity(findings)] >= SEVERITY_ORDER[fail_on]
