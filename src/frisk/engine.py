"""Static scan engine. Zero-execution: reads bytes, matches regex, returns findings."""
from __future__ import annotations

import re
from bisect import bisect_right
from dataclasses import dataclass, asdict, field
from pathlib import Path

from . import surfaces
from .rules import (
    ARCHIVE_EXTS, CODE_EXTS, CODE_RULES, EXECUTABLE_EXTS, MEDIA_EXTS, RULE_META, TEXT_EXTS,
    TEXT_RULES, UNICODE_RULE, executable_magic, hidden_unicode,
)
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


def _not_scanned(rel: str, reason: str, detail: str, rule: str | None = None,
                 message: str = "") -> ScanResult:
    """A file that was not pattern-matched: a skipped entry, plus a warn finding if `rule`."""
    findings = []
    if rule is not None:
        category, severity, _ = RULE_META[rule]
        findings.append(Finding(rel, 1, rule, category, severity, message, ""))
    return ScanResult(findings, Coverage(skipped=[Skipped(rel, reason, detail)]))


def _read_text(path: Path, rel: str) -> str | ScanResult:
    """The file's text (newlines normalised as text-mode reading does), or why not."""
    ext = path.suffix.lower()
    if ext in MEDIA_EXTS:
        return _not_scanned(rel, "binary", ext)
    if ext in EXECUTABLE_EXTS:
        return _not_scanned(rel, "binary", ext, "coverage.binary",
                            f"executable content not scanned ({ext})")
    if ext in ARCHIVE_EXTS:
        return _not_scanned(rel, "binary", ext, "coverage.binary",
                            f"archive not scanned: contents unscanned ({ext})")
    try:
        data = path.read_bytes()
    except OSError as e:
        name = type(e).__name__
        return _not_scanned(rel, "unreadable", name, "coverage.unreadable",
                            f"file could not be read: {name}")
    magic = executable_magic(data)
    if magic is not None:
        return _not_scanned(rel, "binary", magic, "coverage.binary",
                            f"executable content not scanned ({magic})")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        if ext in CODE_EXTS or ext in TEXT_EXTS or data.startswith(b"#!"):
            return _not_scanned(rel, "unreadable", "UnicodeDecodeError", "coverage.unreadable",
                                "file could not be decoded as UTF-8: UnicodeDecodeError")
        return _not_scanned(rel, "binary", "not UTF-8 text")
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _in_target(path: Path, root: Path | None) -> str:
    """The POSIX path of `path` inside the scanned root (see docs/adr/0001-finding-paths.md)."""
    return (path.relative_to(root) if root else path).as_posix()


def scan_file(path: Path, root: Path | None = None) -> ScanResult:
    rel = _in_target(path, root)
    text = _read_text(path, rel)
    if isinstance(text, ScanResult):
        return text
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
        inside = f.relative_to(p).parts
        if ".git" in inside:
            if inside.index(".git") == len(inside) - 1:  # the VCS entry itself, once
                result.coverage.skipped.append(Skipped(_in_target(f, base), "vcs_dir"))
            continue
        if f.is_file():
            result.extend(scan_file(f, base))
    return result.sort()


def display_prefix(target: str, is_file: bool) -> str:
    """The prefix that turns a local target's in-target paths into the paths shown.

    ADR 0001: a directory is the target as given minus leading './' and trailing '/'
    ('.' adds nothing); a single file is reported as the argument verbatim, so its
    prefix is the argument up to the file name.
    """
    if is_file:
        return target[:len(target) - len(Path(target).name)]
    base = target
    while base.startswith("./"):
        base = base[2:]
    base = base.rstrip("/")
    if base in ("", "."):
        return "/" if target.startswith("/") else ""
    return base + "/"


def reroot(result: ScanResult, prefix: str) -> ScanResult:
    """The one place display paths are made: prefix every finding and skipped path.

    Finding paths, coverage.skipped paths and coverage.* finding paths all pass through
    here, so they always follow the same rule (docs/adr/0001-finding-paths.md).
    """
    for f in result.findings:
        f.path = prefix + f.path
    for s in result.coverage.skipped:
        s.path = prefix + s.path
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
