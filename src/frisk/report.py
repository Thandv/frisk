"""Output formatters: human text, JSON, and SARIF 2.1.0 (GitHub code scanning)."""
from __future__ import annotations

import hashlib
import json
import os
import sys
from collections import Counter
from typing import NamedTuple

from .engine import Coverage, Finding, ScanResult, sort_findings, verdict, worst_severity
from .rules import RULE_META, SUSPECT_UNICODE, owasp_for
from .sources import ServerRef, display_ref, display_url

_USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
_C = {
    "block": "\033[31m", "warn": "\033[33m", "pass": "\033[32m",
    "dim": "\033[2m", "bold": "\033[1m", "reset": "\033[0m",
}
_VERDICT_COLOR = {"PASS": "pass", "WARN": "warn", "BLOCK": "block"}


def _c(s: str, key: str) -> str:
    return f"{_C[key]}{s}{_C['reset']}" if _USE_COLOR else s


def _escape(cp: int) -> str:
    return f"\\x{cp:02x}" if cp < 0x100 else f"\\u{cp:04x}" if cp < 0x10000 else f"\\U{cp:08x}"


# C0 and C1 control characters, DEL, and the hidden Unicode frisk reports (bidi, zero-width,
# tag characters, ...): a config or a scanned tree could use them to rewrite the terminal.
# Lone surrogates (a JSON "\ud800", or a file name that is not UTF-8) cannot be printed at all.
_ESCAPES = {cp: _escape(cp) for cp in [*range(0x20), *range(0x7F, 0xA0), *range(0xD800, 0xE000),
                                         *(cp for lo, hi, _n, _s in SUSPECT_UNICODE for cp in range(lo, hi + 1))]}


def printable(text: str) -> str:
    """Text as the text report prints it: control and hidden characters shown as escapes
    (\\x1b, \\u202e). Every config-derived string, finding path and excerpt (scanned content)
    goes through it, and so do the target label and error messages; JSON and SARIF escape
    them as JSON does."""
    return text.translate(_ESCAPES)


class AuditRecord(NamedTuple):
    """One server of an MCP config audit: built by cli._audit_config, formatted here.

    `result` is the server's scan (finding and skipped paths prefixed 'name::');
    `verdict` is None when the server was not scanned.
    """
    server: ServerRef
    result: ScanResult
    verdict: str | None


def audit_text(path: str, records: list[AuditRecord]) -> str:
    """The text audit of one config: a header, one line per server in config order, then
    how many servers were not scanned."""
    lines = [_c(f"MCP config audit: {printable(path)}", "bold"), ""]
    if not records:
        lines.append("  (no servers found in config)")
    for rec in records:
        s = rec.server
        tag = _c("SKIP ", "dim") if rec.verdict is None else _c(f"{rec.verdict:<5}", _VERDICT_COLOR[rec.verdict])
        lines.append(f"  [{tag}] {printable(s.name):<22} {_c(s.kind, 'dim')}  {printable(_reason(s))}")
        if rec.verdict is None:
            lines.append(_c(f"           → {printable(display_ref(s))}", "dim"))
    if records:
        total, skipped = len(records), sum(1 for rec in records if rec.verdict is None)
        noun = "server" if total == 1 else "servers"
        summary = f"{skipped} of {total} {noun} not scanned" if skipped else f"scanned {total} of {total} {noun}"
        lines += ["", "  " + _c(summary, "warn" if skipped else "dim")]
    return "\n".join(lines)


def _reason(s: ServerRef) -> str:
    """The server's detail, plus what was not scanned with it: a cached package's
    dependencies, and a remote URL the entry names beside its command."""
    reason, deps = s.detail, s.unscanned_deps
    if deps:
        reason += f"; {len(deps)} dependenc{'y' if len(deps) == 1 else 'ies'} not scanned: {', '.join(deps)}"
    if s.url:
        reason += f"; the entry also names the remote URL {display_url(s.url)}, which is not scanned"
    return reason


def _audit_servers(records: list[AuditRecord]) -> list[dict]:
    """The servers[] entries of the JSON report: name, kind, status, reason and verdict."""
    return [{"name": rec.server.name, "kind": rec.server.kind,
             "status": "skipped" if rec.verdict is None else "scanned",
             "reason": _reason(rec.server), "verdict": rec.verdict} for rec in records]


# Sized to the longest category any rule can report, so every line aligns.
_CATEGORY_WIDTH = max(len(category) for category, _, _ in RULE_META.values())


def coverage_line(coverage: Coverage) -> str:
    """'scanned N files, skipped M (reason: count, ...)' for the text report."""
    n, skipped = coverage.files_scanned, coverage.skipped
    line = f"scanned {n} file{'' if n == 1 else 's'}, skipped {len(skipped)}"
    if skipped:
        counts = Counter(s.reason for s in skipped)
        line += " (" + ", ".join(f"{r}: {c}" for r, c in sorted(counts.items())) + ")"
    return line


def to_text(result: ScanResult, target: str, show_coverage: bool = True) -> str:
    findings = result.findings
    lines: list[str] = []
    for f in findings:
        mark = _c("BLOCK", "block") if f.severity == "block" else _c("warn ", "warn")
        loc = _c(f"{printable(f.path)}:{f.line}", "dim")
        lines.append(f"[{mark}] {f.category:<{_CATEGORY_WIDTH}} {loc}  {f.description}")
        if f.excerpt:
            lines.append(_c(f"          | {printable(f.excerpt)}", "dim"))
    blocks = sum(1 for f in findings if f.severity == "block")
    warns = sum(1 for f in findings if f.severity == "warn")
    v = verdict(findings)
    banner = _c(f"  {v}  ", _VERDICT_COLOR[v])
    if not findings:
        lines.append(_c(f"frisk: clean — no findings in {printable(target)}", "pass"))
    lines.append("")
    if show_coverage:
        lines.append(_c(coverage_line(result.coverage), "dim"))
    lines.append(f"{_c('verdict', 'bold')}: {banner}  "
                 f"{blocks} blocking · {warns} warnings · {len(findings)} total  "
                 f"({_c(printable(target), 'dim')})")
    return "\n".join(lines)


def to_json(result: ScanResult, target: str, servers: list[AuditRecord] | None = None) -> str:
    """The JSON report; `servers` (one entry per audited MCP server) is present only when
    an MCP config was audited."""
    findings = result.findings
    doc: dict[str, object] = {
        "target": target,
        "verdict": verdict(findings),
        "worst_severity": worst_severity(findings),
        "counts": {
            "block": sum(1 for f in findings if f.severity == "block"),
            "warn": sum(1 for f in findings if f.severity == "warn"),
            "total": len(findings),
        },
        "findings": [{**f.as_dict(), "owasp": owasp_for(f.category)} for f in findings],
        "coverage": result.coverage.as_dict(),
    }
    if servers is not None:
        doc["servers"] = _audit_servers(servers)
    return json.dumps(doc, indent=2)


_SARIF_LEVEL = {"block": "error", "warn": "warning"}
_SECURITY_SEVERITY = {"block": "8.5", "warn": "5.0"}
_INFO_URI = "https://github.com/Thandv/frisk"
_HELP_URI = _INFO_URI + "/blob/main/docs/rules.md#"


def _sarif_path(path: str) -> str:
    """A local path as a SARIF uri: POSIX, and relative to cwd if it was absolute.

    The plain relpath is used unless it climbs out of cwd while the resolved paths do
    not (e.g. macOS /var vs /private/var), so a file inside cwd never gets a '../' uri.
    """
    if os.path.isabs(path):
        rel = os.path.relpath(path)
        if rel.startswith(os.pardir):
            real = os.path.relpath(os.path.realpath(path), os.path.realpath(os.curdir))
            if not real.startswith(os.pardir):
                rel = real
        path = rel
    return path.replace(os.sep, "/")


def _location(f: Finding) -> dict:
    """The SARIF location for a finding's origin (docs/adr/0001-finding-paths.md)."""
    if f.origin in ("text", "mcp"):
        return {"logicalLocations": [{"fullyQualifiedName": f.path}]}
    artifact = {"uri": _sarif_path(f.path) if f.origin == "local" else f.path}
    if f.origin == "git":
        artifact["uriBaseId"] = "SRCROOT"
    return {"physicalLocation": {"artifactLocation": artifact,
                                 "region": {"startLine": max(1, f.line)}}}


def normalise_line(source_line: str) -> str:
    """The source line as fingerprinted: trimmed, internal whitespace collapsed to one space."""
    return " ".join(source_line.split())


def fingerprint(rule: str, path: str, line_text: str, occurrence: int) -> str:
    """frisk/v1: sha256 of rule, path, the normalised source line and the occurrence index
    among results with the same first three, NUL-separated. The line number is deliberately
    absent, so inserting lines above a finding keeps it."""
    parts = (rule, path, line_text, str(occurrence))
    return hashlib.sha256("\0".join(parts).encode("utf-8", "surrogatepass")).hexdigest()


def to_sarif(result: ScanResult, version: str) -> str:
    """SARIF 2.1.0 so GitHub's code-scanning Security tab renders findings inline.

    Deterministic: rules sorted by id, results by (path, line, rule), keys sorted, no
    timestamps, and no absolute paths for local targets.
    """
    findings = sort_findings(result.findings)
    rules = []
    for rid in sorted({f.rule for f in findings}):
        category, severity, description = RULE_META[rid]
        rules.append({
            "id": rid,
            "name": rid,
            "shortDescription": {"text": description},
            "helpUri": _HELP_URI + rid,
            "properties": {
                "category": category,
                "owasp": owasp_for(category),
                "security-severity": _SECURITY_SEVERITY.get(severity, "2.0"),
            },
        })
    seen: Counter[tuple[str, str, str]] = Counter()
    results = []
    for f in findings:
        location = _location(f)
        physical = location.get("physicalLocation")
        path = physical["artifactLocation"]["uri"] if physical else f.path
        key = (f.rule, path, normalise_line(f.source_line))
        results.append({
            "ruleId": f.rule,
            "level": _SARIF_LEVEL.get(f.severity, "note"),
            "message": {"text": f.description + (f"  ¦ {f.excerpt}" if f.excerpt else "")},
            "locations": [location],
            "partialFingerprints": {"frisk/v1": fingerprint(*key, seen[key])},
        })
        seen[key] += 1
    coverage = result.coverage.as_dict()
    for entry in coverage["skipped"]:
        entry["path"] = _sarif_path(entry["path"])
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "frisk",
                "informationUri": _INFO_URI,
                "version": version,
                "rules": rules,
            }},
            "results": results,
            "properties": {"coverage": coverage},
        }],
    }
    return json.dumps(doc, indent=2, sort_keys=True)
