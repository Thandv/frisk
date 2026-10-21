"""Output formatters: human text, JSON, and SARIF 2.1.0 (GitHub code scanning)."""
from __future__ import annotations

import hashlib
import json
import os
import sys
from collections import Counter

from .engine import Coverage, Finding, ScanResult, sort_findings, verdict, worst_severity
from .rules import RULE_META, owasp_for

_USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
_C = {
    "block": "\033[31m", "warn": "\033[33m", "pass": "\033[32m",
    "dim": "\033[2m", "bold": "\033[1m", "reset": "\033[0m",
}


def _c(s: str, key: str) -> str:
    return f"{_C[key]}{s}{_C['reset']}" if _USE_COLOR else s


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
        loc = _c(f"{f.path}:{f.line}", "dim")
        lines.append(f"[{mark}] {f.category:<{_CATEGORY_WIDTH}} {loc}  {f.description}")
        if f.excerpt:
            lines.append(_c(f"          | {f.excerpt}", "dim"))
    blocks = sum(1 for f in findings if f.severity == "block")
    warns = sum(1 for f in findings if f.severity == "warn")
    v = verdict(findings)
    vkey = {"PASS": "pass", "WARN": "warn", "BLOCK": "block"}[v]
    banner = _c(f"  {v}  ", vkey)
    if not findings:
        lines.append(_c(f"frisk: clean — no findings in {target}", "pass"))
    lines.append("")
    if show_coverage:
        lines.append(_c(coverage_line(result.coverage), "dim"))
    lines.append(f"{_c('verdict', 'bold')}: {banner}  "
                 f"{blocks} blocking · {warns} warnings · {len(findings)} total  "
                 f"({_c(target, 'dim')})")
    return "\n".join(lines)


def to_json(result: ScanResult, target: str) -> str:
    findings = result.findings
    return json.dumps({
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
    }, indent=2)


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
    return hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()


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
