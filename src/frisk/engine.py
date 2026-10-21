"""Static scan engine. Zero-execution: reads bytes, matches regex, returns findings."""
from __future__ import annotations

import os
import posixpath
import re
from bisect import bisect_right
from dataclasses import dataclass, asdict, field
from pathlib import Path

from . import surfaces
from .rules import (
    ARCHIVE_EXTS, CODE_EXTS, CODE_RULES, EXECUTABLE_EXTS, MEDIA_EXTS, OPAQUE_DATA_EXTS, RULE_META,
    TEXT_EXTS, TEXT_RULES, UNICODE_RULE, executable_magic, hidden_unicode,
)
from .surfaces import Span

_NEWLINE = re.compile("\n")

SEVERITY_ORDER = {None: 0, "warn": 1, "block": 2}
_INTERNAL_FIELDS = ("origin", "source_line")


@dataclass
class Finding:
    path: str
    line: int
    rule: str
    category: str
    severity: str
    description: str
    excerpt: str
    # Not part of the JSON finding: where the path points (docs/adr/0001-finding-paths.md:
    # "local", "git", "mcp" or "text"), and the full source line, for SARIF fingerprints.
    origin: str = "local"
    source_line: str = ""

    def as_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if k not in _INTERNAL_FIELDS}


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
        end = starts[line] - 1 if line < len(starts) else len(text)
        out.append(Finding(rel, line, rid, cat, sev, desc, excerpt,
                           source_line=text[starts[line - 1]:end]))

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
    findings = _scan_spans(text, [Span(0, whole, "code"), Span(0, whole, "text")], label)
    for f in findings:
        f.origin = "text"
    return ScanResult(findings)


def _not_scanned(rel: str, reason: str, detail: str, rule: str | None = None,
                 message: str = "") -> ScanResult:
    """A file that was not pattern-matched: a skipped entry, plus a warn finding if `rule`."""
    findings = []
    if rule is not None:
        category, severity, _ = RULE_META[rule]
        findings.append(Finding(rel, 1, rule, category, severity, message, ""))
    return ScanResult(findings, Coverage(skipped=[Skipped(rel, reason, detail)]))


def _read_text(path: Path, rel: str) -> tuple[str | None, ScanResult]:
    """The file's text (newlines normalised as text-mode reading does), plus coverage notes.

    Text is None when the file cannot be pattern-matched at all. A text-like file that is
    not valid UTF-8 is still scanned, with undecodable bytes replaced, and also warns:
    one invalid byte must not hide the rest of the file.
    """
    ext = path.suffix.lower()
    if ext == ".":  # Python 3.14 reports 'name.' as suffix '.', 3.9 as '': no extension
        ext = ""
    if ext in MEDIA_EXTS:
        return None, _not_scanned(rel, "binary", ext)
    if ext in EXECUTABLE_EXTS:
        return None, _not_scanned(rel, "binary", ext, "coverage.binary",
                                  f"executable content not scanned ({ext})")
    if ext in ARCHIVE_EXTS:
        return None, _not_scanned(rel, "binary", ext, "coverage.binary",
                                  f"archive not scanned: contents unscanned ({ext})")
    try:
        data = path.read_bytes()
    except OSError as e:
        name = type(e).__name__
        return None, _not_scanned(rel, "unreadable", name, "coverage.unreadable",
                                  f"file could not be read: {name}")
    notes = ScanResult()
    try:
        text = data.decode("utf-8-sig")  # a leading BOM is encoding, not content
    except UnicodeDecodeError:
        # Valid UTF-8 is always scanned. Content that does not decode is scanned lossily
        # and warns, unless it is clearly not text: executable magic on a file with no
        # code/text extension or shebang (coverage.binary), an opaque data format (silent),
        # or NUL bytes in a file with an unlisted extension (coverage.binary). Files with
        # no extension (Dockerfile, .bashrc, hooks) are always scanned unless magic matches.
        textual = ext in CODE_EXTS or ext in TEXT_EXTS or data.removeprefix(b"\xef\xbb\xbf").startswith(b"#!")
        magic = None if textual else executable_magic(data)
        if magic is not None:
            return None, _not_scanned(rel, "binary", magic, "coverage.binary",
                                      f"executable content not scanned ({magic})")
        if not textual and ext in OPAQUE_DATA_EXTS:
            return None, _not_scanned(rel, "binary", "not UTF-8 text")
        if not textual and ext and b"\0" in data:
            return None, _not_scanned(rel, "binary", "not UTF-8 text", "coverage.binary",
                                      f"binary content not scanned ({ext})")
        notes = _not_scanned(rel, "unreadable", "UnicodeDecodeError", "coverage.unreadable",
                             "file is not valid UTF-8 (UnicodeDecodeError); "
                             "scanned with undecodable bytes replaced")
        text = data.decode("utf-8-sig", errors="replace")
    # NUL bytes are dropped: shells ignore them, so 'c<NUL>url' must still match as 'curl'.
    return text.replace("\r\n", "\n").replace("\r", "\n").replace("\0", ""), notes


def _in_target(path: Path, root: Path | None) -> str:
    """The POSIX path of `path` inside the scanned root (see docs/adr/0001-finding-paths.md)."""
    return (path.relative_to(root) if root else path).as_posix()


def scan_file(path: Path, root: Path | None = None) -> ScanResult:
    rel = _in_target(path, root)
    text, notes = _read_text(path, rel)
    if text is None:
        return notes
    spans: list[Span] = []
    for surface in surfaces.load():
        try:
            spans.extend(surface.extract(path, text))
        except Exception as e:  # noqa: BLE001 - one broken surface must not stop the scan
            detail = f"{surfaces.name_of(surface)}: {type(e).__name__}"
            notes.extend(_not_scanned(rel, "surface_error", detail, "coverage.surface_error",
                                      f"scan surface failed on this file ({detail})"))
    result = ScanResult(_scan_spans(text, spans, rel), Coverage(files_scanned=1))
    result.extend(notes)
    return result.sort()


def scan_path(path: str | Path, root: Path | None = None) -> ScanResult:
    p = Path(path)
    if p.is_file():
        return scan_file(p, root or p.parent)
    result = ScanResult()
    base = root or p
    _check_listable(p, base, result)
    for f in sorted(p.rglob("*")):
        inside = f.relative_to(p).parts
        if ".git" in inside and not (inside[-1] == ".git" and f.is_file()):  # a gitfile is scanned
            if inside.index(".git") == len(inside) - 1:  # the VCS directory itself, once
                rel = _in_target(f, base)
                if len(inside) > 1 and f.is_dir():
                    # Below the top, a .git directory is an easy hiding place: warn.
                    result.extend(_not_scanned(rel, "vcs_dir", "nested", "coverage.nested_vcs",
                                               "nested .git directory not scanned"))
                else:
                    result.coverage.skipped.append(Skipped(rel, "vcs_dir"))
            continue
        if f.is_file():
            result.extend(scan_file(f, base))
        elif f.is_dir():
            _check_listable(f, base, result)
    return result.sort()


def _check_listable(directory: Path, base: Path, result: ScanResult) -> None:
    """rglob silently skips a directory it cannot list; record it as unreadable instead."""
    try:
        with os.scandir(directory):
            pass
    except OSError as e:
        name = type(e).__name__
        result.extend(_not_scanned(_in_target(directory, base), "unreadable", name,
                                   "coverage.unreadable", f"directory could not be listed: {name}"))


def display_prefix(target: str, is_file: bool) -> str:
    """The prefix that turns a local target's in-target paths into the paths shown.

    ADR 0001: a directory is the target as given, normalised with posixpath.normpath (no
    './', '//', '/.' or trailing '/', and 'a/../b' -> 'b'; '.' adds nothing); a single
    file is reported as the argument verbatim, so its prefix is the argument up to the
    file name.
    """
    if is_file:
        return target[:len(target) - len(Path(target).name)]
    base = posixpath.normpath(target.replace(os.sep, "/"))
    if base.startswith("//"):  # POSIX keeps a leading '//'; frisk treats it as '/'
        base = "/" + base.lstrip("/")
    if base == ".":
        return ""
    return base if base.endswith("/") else base + "/"


def reroot(result: ScanResult, prefix: str, origin: str) -> ScanResult:
    """The one place display paths are made: prefix every finding and skipped path.

    Finding paths, coverage.skipped paths and coverage.* finding paths all pass through
    here, so they always follow the same rule (docs/adr/0001-finding-paths.md). `origin`
    ("local", "git" or "mcp") tells SARIF which location form the path takes.
    """
    for f in result.findings:
        f.path = prefix + f.path
        f.origin = origin
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
