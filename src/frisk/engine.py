"""Static scan engine. Zero-execution: reads bytes, matches regex, returns findings."""
from __future__ import annotations

import os
import posixpath
import re
import stat
import time
from bisect import bisect_right
from dataclasses import dataclass, asdict, field
from pathlib import Path

from . import surfaces, walk
from .debug import log as _root_log
from .redact import Redactor
from .rules import (
    ARCHIVE_EXTS, CODE_EXTS, CODE_RULES, EXECUTABLE_EXTS, MEDIA_EXTS, OPAQUE_DATA_EXTS, RULE_META,
    INSTRUCTION_RULES, TEXT_EXTS, TEXT_RULES, executable_magic, hidden_unicode,
)
from .surfaces import Span

log = _root_log.getChild("engine")

_NEWLINE = re.compile("\n")

# Scan bounds (ScanLimits' defaults). A file larger than MAX_FILE_BYTES is not read; a text
# longer than MAX_FILE_BYTES characters is matched in a head and a tail window (scan_text).
MAX_FILES = 20_000
MAX_FILE_BYTES = 2 * 1024 * 1024

SEVERITY_ORDER = {None: 0, "warn": 1, "block": 2}
_INTERNAL_FIELDS = ("origin", "source_line")


@dataclass(frozen=True)
class ScanLimits:
    """Bounds on one scan_path call. A file over max_file_bytes is not read (reason
    too_large, a coverage.too_large block finding). The walk stops before the next file once
    max_files files were looked at, max_bytes bytes were read, or deadline_s seconds have
    passed (file_cap, byte_cap, deadline: a coverage.unscanned warning). So the verdict is
    never PASS."""
    max_files: int = MAX_FILES
    max_file_bytes: int = MAX_FILE_BYTES
    max_bytes: int | None = None
    deadline_s: float | None = None


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


def _excerpt(secrets: Redactor, span: Span, idx: int, after: int = 80) -> str:
    """The text around offset `idx` (10 characters before, `after` from it), inside the span,
    with its secrets masked."""
    snippet = secrets.window(max(span.start, idx - 10), min(span.end, idx + after)).replace("\n", "\\n")
    return snippet.strip()[:120]


# Kinds with their own rules; every other kind is a text kind: TEXT_RULES and the hidden-
# Unicode check. scan_text over its bound splits those two: "window" (the rules on a head
# or tail window) and "unicode" (the check on the whole text).
_RULES_FOR_KIND = {"code": CODE_RULES, "md_inline_code": CODE_RULES, "instruction": INSTRUCTION_RULES,
                   "window": TEXT_RULES, "unicode": []}
_WARN_CAPPED_KINDS = {"md_inline_code"}  # a block finding from these spans reports as warn


def _scan_span(text: str, span: Span, starts: list[int], rel: str, out: list[Finding],
               seen: set[tuple[int, str]], secrets: Redactor) -> None:
    """Run the span's rules on text[span.start:span.end]; lines are file lines.

    The span is matched as its own string (so ^, lookbehinds and word boundaries see the
    span's edges, as they always have) and its excerpts stay inside it; offsets are
    shifted by span.start and mapped to a line through the file's line index. A rule that
    matched at the same file offset in an earlier, overlapping span is reported once.
    """
    seg = text if (span.start, span.end) == (0, len(text)) else text[span.start:span.end]

    def add(idx: int, rid: str, cat: str, sev: str, desc: str, excerpt: str) -> None:
        if (span.start + idx, rid) in seen:
            return
        seen.add((span.start + idx, rid))
        line = bisect_right(starts, span.start + idx)
        end = starts[line] - 1 if line < len(starts) else len(text)
        out.append(Finding(rel, line, rid, cat, sev, desc, excerpt,
                           source_line=text[starts[line - 1]:end]))

    capped = span.kind in _WARN_CAPPED_KINDS
    for rid, cat, sev, rx, desc in _RULES_FOR_KIND.get(span.kind, TEXT_RULES):
        if capped and sev == "block":
            sev = "warn"
        for m in rx.finditer(seg):
            add(m.start(), rid, cat, sev, desc, _excerpt(secrets, span, span.start + m.start()))
    if span.kind not in _RULES_FOR_KIND or span.kind == "unicode":  # every text kind
        for idx, rid, desc in hidden_unicode(seg, span.start == 0):
            cat, sev, _ = RULE_META[rid]
            add(idx, rid, cat, sev, desc, "")


def _scan_spans(text: str, spans: list[Span], rel: str) -> list[Finding]:
    starts = _line_starts(text)
    out: list[Finding] = []
    seen: set[tuple[int, str]] = set()
    secrets = Redactor(text)
    # Capped spans go last, so a match also found by an uncapped span keeps its severity.
    for span in sorted(spans, key=lambda s: s.kind in _WARN_CAPPED_KINDS):
        _scan_span(text, span, starts, rel, out, seen, secrets)
    return sort_findings(out)


def scan_text(text: str, label: str = "<text>", max_chars: int = MAX_FILE_BYTES) -> ScanResult:
    """Scan a raw string as both code and prose (--text, frisk-mcp, the proxy).

    The one truncation policy for every caller: a text longer than `max_chars` has the rules
    run on its first and last max_chars // 2 characters (lines count from the start of the
    whole text), the hidden-Unicode check on all of it, and a coverage.truncated warning, so
    the verdict is never PASS.
    """
    whole = len(text)
    if whole <= max_chars:
        findings = _scan_spans(text, [Span(0, whole, "code"), Span(0, whole, "text")], label)
    else:
        half = max_chars // 2
        windows = [Span(start, end, kind) for start, end in ((0, half), (whole - half, whole))
                   for kind in ("code", "window")]
        findings = _scan_spans(text, windows + [Span(0, whole, "unicode")], label)
        category, severity, _ = RULE_META["coverage.truncated"]
        findings = sort_findings(findings + [Finding(
            label, 1, "coverage.truncated", category, severity,
            f"text of {whole} characters is over the {max_chars}-character limit: only its first and last "
            f"{half} were pattern-matched (the hidden-Unicode check read it all)", "")])
    for f in findings:
        f.origin = "text"
    return ScanResult(findings)


def coverage_warning(rel: str, rule: str, message: str) -> ScanResult:
    """A coverage finding (a rule in RULE_META) about `rel` as a whole, at line 1."""
    category, severity, _ = RULE_META[rule]
    return ScanResult([Finding(rel, 1, rule, category, severity, message, "")])


def _not_scanned(rel: str, reason: str, detail: str, rule: str | None = None,
                 message: str = "") -> ScanResult:
    """A file that was not pattern-matched: a skipped entry, plus a `rule` finding if given."""
    result = coverage_warning(rel, rule, message) if rule is not None else ScanResult()
    result.coverage.skipped.append(Skipped(rel, reason, detail))
    return result


def _read_text(path: Path, rel: str, max_bytes: int | None) -> tuple[str | None, ScanResult]:
    """The file's text (newlines normalised as text-mode reading does), plus coverage notes.

    Text is None when the file cannot be pattern-matched at all, or is larger than
    `max_bytes` (checked before reading). A text-like file that is
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
        st = os.lstat(path)  # never read through a symlink, never open a FIFO, socket or device
        if stat.S_ISLNK(st.st_mode):
            return None, _not_scanned(rel, "special", "symlink")
        if not stat.S_ISREG(st.st_mode):
            return None, _not_scanned(rel, "special", walk.special_kind(st.st_mode))
        size = st.st_size
        if max_bytes is not None and size > max_bytes:
            return None, _not_scanned(rel, "too_large", f"{size} bytes", "coverage.too_large",
                                      f"file not scanned: {size} bytes is over the {max_bytes}-byte limit; "
                                      f"raise --max-file-bytes to scan it, or leave it out of the target")
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
    return text.replace("\r\n", "\n").replace("\r", "\n"), notes


def _in_target(path: Path, root: Path | None) -> str:
    """The POSIX path of `path` inside the scanned root (see docs/adr/0001-finding-paths.md)."""
    return (path.relative_to(root) if root else path).as_posix()


def scan_file(path: Path, root: Path | None = None, max_bytes: int | None = None) -> ScanResult:
    """Scan one file; one larger than `max_bytes` (None: no bound) is not read."""
    rel = _in_target(path, root)
    text, notes = _read_text(path, rel, max_bytes)
    if text is None:
        return notes
    failed: dict[str, None] = {}  # surface failures, in order, reported once per file
    findings = _scan_reading(path, text, rel, failed)
    if "\0" in text:
        # NUL bytes make two readings: as written (a renderer shows NUL as U+FFFD, so it
        # cannot close a fence) and with NUL dropped (shells drop it, so 'c<NUL>url' runs as
        # 'curl'). A finding from either reading counts, once, at the higher of its two
        # severities: one reading may see as capped inline code what the other sees as a
        # code block.
        first: dict[tuple[int, str, str], list[Finding]] = {}
        for f in findings:
            first.setdefault((f.line, f.rule, f.description), []).append(f)
        for f in _scan_reading(path, text.replace("\0", ""), rel, failed):
            same = first.get((f.line, f.rule, f.description))
            if same is None:
                findings.append(f)
                continue
            for g in same:
                g.severity = max(g.severity, f.severity, key=SEVERITY_ORDER.__getitem__)
    for detail in failed:
        notes.extend(_not_scanned(rel, "surface_error", detail, "coverage.surface_error",
                                  f"scan surface failed on this file ({detail})"))
    result = ScanResult(findings, Coverage(files_scanned=1))
    result.extend(notes)
    return result.sort()


def _scan_reading(path: Path, text: str, rel: str, failed: dict[str, None]) -> list[Finding]:
    """Run every surface on `text` and match its spans; a failing surface is noted in `failed`."""
    spans: list[Span] = []
    for surface in surfaces.load():
        try:
            spans.extend(surface.extract(path, text))
        except Exception as e:  # noqa: BLE001 - one broken surface must not stop the scan
            failed[f"{surfaces.name_of(surface)}: {type(e).__name__}"] = None
    return _scan_spans(text, spans, rel)


def scan_path(path: str | Path, root: Path | None = None, limits: ScanLimits | None = None) -> ScanResult:
    """Scan a file or a directory tree within `limits` (default: ScanLimits()).

    Nothing outside the scan root is read: a symlink (also a single-file target that is
    one) whose target lies outside it is an fs.symlink_escape finding, never opened."""
    limits = limits or ScanLimits()
    p = Path(path)
    if os.path.islink(p) and not p.is_dir():  # a symlinked directory named as the target is walked
        base = root or p.parent
        return _link(p, base, Path(os.path.realpath(base)), limits.max_file_bytes, set())[0].sort()
    if p.is_file() or (p.exists() and not p.is_dir()):  # a FIFO, socket or device: skipped as special
        return scan_file(p, root or p.parent, limits.max_file_bytes)
    result = ScanResult()
    base = root or p
    stopped = _walk(p, base, limits, result)
    # Skipped entries in the order a sorted listing of the whole tree gives (a directory
    # before what is in it), whatever order the walk met them in.
    result.coverage.skipped.sort(key=lambda s: s.path.split("/"))
    if stopped is not None:
        reason, detail, message = stopped
        result.extend(_not_scanned(_in_target(p, base), reason, detail, "coverage.unscanned", message))
    return result.sort()


def _walk(top: Path, base: Path, limits: ScanLimits, result: ScanResult) -> tuple[str, str, str] | None:
    """Scan the files below `top` into `result` (walk.entries: name order, no symlink
    followed, no .git directory entered). A symlink to a file inside the root is scanned
    once, at the target's path. Returns (reason, detail, message) for the limit that
    stopped the walk, or None when it went through the tree."""
    started = time.monotonic()
    looked_at = read = 0
    base_real = Path(os.path.realpath(base))
    scanned: set[str] = set()  # in-target paths already read, so a linked file is read once

    def unlistable(err: OSError) -> None:
        name = type(err).__name__
        where = Path(err.filename) if err.filename is not None else top
        result.extend(_not_scanned(_in_target(where, base), "unreadable", name, "coverage.unreadable",
                                   f"directory could not be listed: {name}"))

    for entry in walk.entries(top, onerror=unlistable):
        if entry.kind == "dir":
            if limits.deadline_s is not None and time.monotonic() - started >= limits.deadline_s:
                return _limit_hit(limits, looked_at, read, started)  # also between directories with no files
            continue
        if entry.kind == "vcs":
            _vcs_dir(entry.path, base, nested=entry.nested, result=result)
            continue
        if entry.kind == "dir_link":  # listed as an entry, never entered
            link = walk.read_link(entry.path, base_real)
            if link.inside:
                _check_listable(entry.path, base, result)
            else:
                result.extend(_escape(_in_target(entry.path, base), link))
            continue
        if entry.kind == "special":
            result.coverage.skipped.append(Skipped(_in_target(entry.path, base), "special", entry.detail))
            continue
        hit = _limit_hit(limits, looked_at, read, started)
        if hit is not None:
            return hit
        if entry.kind == "link":
            found, target = _link(entry.path, base, base_real, limits.max_file_bytes, scanned)
        elif _in_target(entry.path, base) in scanned:  # already read through a link to it
            continue
        else:
            target = entry.path
            scanned.add(_in_target(target, base))
            found = scan_file(target, base, limits.max_file_bytes)
        looked_at += 1
        if found.coverage.files_scanned and target is not None:
            read += _size(target)
        result.extend(found)
    return None


def _size(path: Path) -> int:
    try:
        return os.lstat(path).st_size
    except OSError:  # gone since it was read: counts as nothing
        return 0


def _link(link_path: Path, base: Path, base_real: Path, max_bytes: int | None,
          scanned: set[str]) -> tuple[ScanResult, Path | None]:
    """A symlink that is not to a directory, and the file read for it (None: none).
    Outside the root: an fs.symlink_escape finding, never read. Inside: the target is
    scanned at its own path, once (`scanned`); a link that loops is skipped as 'loop', a
    dangling one as before (nothing to read)."""
    link = walk.read_link(link_path, base_real)
    rel = _in_target(link_path, base)
    if not link.inside:
        return _escape(rel, link), None
    if walk.is_loop(link_path):
        return _not_scanned(rel, "loop", link.text), None
    if not link.real.exists():
        log.debug("entry skipped (dangling symlink)")
        return ScanResult(), None
    target = base / link.real.relative_to(base_real)
    where = _in_target(target, base)
    if where in scanned:
        return ScanResult(), None
    scanned.add(where)
    return scan_file(target, base, max_bytes), target


def _escape(rel: str, link: walk.Link) -> ScanResult:
    """The fs.symlink_escape finding for a link out of the root: paths only, no excerpt."""
    category, _, _ = RULE_META["fs.symlink_escape"]
    severity = "block" if link.credential else "warn"
    where = "a credential location" if link.credential else "outside the scanned tree"
    result = ScanResult([Finding(rel, 1, "fs.symlink_escape", category, severity,
                                 f"symlink {rel} points {where} ({link.text}); not read", "")])
    result.coverage.skipped.append(Skipped(rel, "symlink_escape", link.text))
    return result


def _limit_hit(limits: ScanLimits, looked_at: int, read: int, started: float) -> tuple[str, str, str] | None:
    rest = "the rest of the tree was not scanned"
    if limits.deadline_s is not None and time.monotonic() - started >= limits.deadline_s:
        return "deadline", f"{limits.deadline_s:g} s", f"scan stopped after {limits.deadline_s:g} s: {rest}"
    if looked_at >= limits.max_files:
        return "file_cap", f"{limits.max_files} files", f"scan stopped after {limits.max_files} files: {rest}"
    if limits.max_bytes is not None and read >= limits.max_bytes:
        return "byte_cap", f"{limits.max_bytes} bytes", f"scan stopped after reading {limits.max_bytes} bytes: {rest}"
    return None


def _vcs_dir(entry: Path, base: Path, nested: bool, result: ScanResult) -> None:
    """A .git entry that is not a file: not scanned. A directory below the top warns."""
    rel = _in_target(entry, base)
    if nested and entry.is_dir():
        # Below the top, a .git directory is an easy hiding place: warn.
        result.extend(_not_scanned(rel, "vcs_dir", "nested", "coverage.nested_vcs",
                                   "nested .git directory not scanned"))
    else:
        result.coverage.skipped.append(Skipped(rel, "vcs_dir"))


def _check_listable(directory: Path, base: Path, result: ScanResult) -> None:
    """A symlinked directory is not walked into; one that cannot be listed is recorded as unreadable."""
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
        f.path = _join(prefix, f.path)
        f.origin = origin
    for s in result.coverage.skipped:
        s.path = _join(prefix, s.path)
    return result.sort()


def _join(prefix: str, path: str) -> str:
    """prefix + path, except that the target directory itself ('.') is the target as named."""
    if path == "." and prefix.endswith("/"):
        return prefix.rstrip("/") or "/"
    return prefix + path


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
