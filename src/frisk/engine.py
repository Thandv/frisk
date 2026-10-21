"""Static scan engine. Zero-execution: reads bytes, matches regex, returns findings."""
from __future__ import annotations

import re
from bisect import bisect_right
from dataclasses import dataclass, asdict, field
from pathlib import Path

from . import surfaces
from .rules import SKIP_EXTS, CODE_RULES, TEXT_RULES, UNICODE_RULE, hidden_unicode
from .surfaces import Span

_NEWLINE = re.compile("\n")

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
    """A file or directory the scan did not pattern-match (or a surface that failed on a file), and why."""
    path: str
    reason: str
    detail: str = ""

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


def _line_starts(text: str) -> list[int]:
    """Offsets where each line begins; built once per scanned text."""
    return [0] + [m.end() for m in _NEWLINE.finditer(text)]


def _excerpt(text: str, idx: int, span: int = 80) -> str:
    start = max(0, idx - 10)
    snippet = text[start:idx + span].replace("\n", "\\n")
    return snippet.strip()[:120]


def _scan_span(text: str, span: Span, starts: list[int], rel: str, out: list[Finding]) -> None:
    """Run the span's rules on text[span.start:span.end]; lines are file lines.

    The span is matched as its own string (so ^, lookbehinds and word boundaries see the
    span's edges, as they always have) and its excerpts stay inside it; offsets are
    shifted by span.start and mapped to a line through the file's line index.
    """
    seg = text if (span.start, span.end) == (0, len(text)) else text[span.start:span.end]

    def add(idx: int, rid: str, cat: str, sev: str, desc: str, excerpt: str) -> None:
        line = bisect_right(starts, span.start + idx)
        out.append(Finding(rel, line, rid, cat, sev, desc, excerpt))

    for rid, cat, sev, rx, desc in (CODE_RULES if span.kind == "code" else TEXT_RULES):
        for m in rx.finditer(seg):
            add(m.start(), rid, cat, sev, desc, _excerpt(seg, m.start()))
    if span.kind == "text":
        rid, cat, sev = UNICODE_RULE
        for idx, desc in hidden_unicode(seg):
            add(idx, rid, cat, sev, desc, "")


def _scan_spans(text: str, spans: list[Span], rel: str) -> list[Finding]:
    starts = _line_starts(text)
    out: list[Finding] = []
    for span in spans:
        _scan_span(text, span, starts, rel, out)
    return sort_findings(out)


def scan_text(text: str, label: str = "<text>") -> ScanResult:
    """Scan a raw string as both code and prose (used by the MCP server / --text)."""
    whole = len(text)
    return ScanResult(_scan_spans(text, [Span(0, whole, "code"), Span(0, whole, "text")], label))


def scan_file(path: Path, root: Path | None = None) -> ScanResult:
    rel = str(path.relative_to(root)) if root else str(path)
    if path.suffix.lower() in SKIP_EXTS:
        return ScanResult()
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return ScanResult()  # binary or unreadable -> not pattern-scannable
    coverage = Coverage(files_scanned=1)
    spans: list[Span] = []
    for surface in surfaces.load():
        try:
            spans.extend(surface.extract(path, text))
        except Exception as e:  # noqa: BLE001 - one broken surface must not stop the scan
            coverage.skipped.append(Skipped(rel, "surface_error",
                                            f"{surfaces.name_of(surface)}: {type(e).__name__}"))
    return ScanResult(_scan_spans(text, spans, rel), coverage)


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
