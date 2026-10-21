"""Static scan engine. Zero-execution: reads bytes, matches regex, returns findings."""
from __future__ import annotations

from dataclasses import dataclass, asdict, field
from pathlib import Path

from .rules import (
    CODE_EXTS, SKIP_EXTS, FENCE_RE, CODE_RULES, TEXT_RULES, UNICODE_RULE, hidden_unicode,
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


@dataclass
class Skipped:
    """A file or directory the scan did not pattern-match, and why."""
    path: str
    reason: str

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class Coverage:
    """What a scan read: how many files were pattern-matched and what was skipped."""
    files_scanned: int = 0
    skipped: list[Skipped] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"files_scanned": self.files_scanned,
                "skipped": [s.as_dict() for s in self.skipped]}


@dataclass
class ScanResult:
    """Findings, sorted by (path, line, rule), plus the coverage of the scan."""
    findings: list[Finding] = field(default_factory=list)
    coverage: Coverage = field(default_factory=Coverage)

    def extend(self, other: ScanResult) -> None:
        """Merge another result into this one; call sort() once merging is done."""
        self.findings.extend(other.findings)
        self.coverage.files_scanned += other.coverage.files_scanned
        self.coverage.skipped.extend(other.coverage.skipped)

    def sort(self) -> ScanResult:
        """Return self with findings in the one canonical order (see sort_findings)."""
        self.findings = sort_findings(self.findings)
        return self


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """The one ordering of findings everywhere: (path, line, rule), stable otherwise."""
    return sorted(findings, key=lambda f: (f.path, f.line, f.rule))


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
    rid, cat, sev = UNICODE_RULE
    for idx, desc in hidden_unicode(text):
        out.append(Finding(rel, _line_of(text, idx), rid, cat, sev, desc, ""))


def scan_text(text: str, label: str = "<text>") -> ScanResult:
    """Scan a raw string as both code and prose (used by the MCP server / --text)."""
    out: list[Finding] = []
    _scan_code(text, label, out)
    _scan_text(text, label, out)
    return ScanResult(sort_findings(out))


def scan_file(path: Path, root: Path | None = None) -> ScanResult:
    rel = str(path.relative_to(root)) if root else str(path)
    ext = path.suffix.lower()
    if ext in SKIP_EXTS:
        return ScanResult()
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return ScanResult()  # binary or unreadable -> not pattern-scannable
    out: list[Finding] = []
    if ext in CODE_EXTS:
        _scan_code(text, rel, out)
        _scan_text(text, rel, out)
    else:
        _scan_text(text, rel, out)
        for m in FENCE_RE.finditer(text):
            _scan_code(m.group(1), rel, out)
    return ScanResult(sort_findings(out), Coverage(files_scanned=1))


def scan_path(path: str | Path, root: Path | None = None) -> ScanResult:
    p = Path(path)
    if p.is_file():
        return scan_file(p, root or p.parent)
    result = ScanResult()
    base = root or p
    for f in sorted(p.rglob("*")):
        if f.is_file() and ".git" not in f.parts:
            result.extend(scan_file(f, base))
    return result.sort()


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
