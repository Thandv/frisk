"""Output formatters: human text, JSON, and SARIF 2.1.0 (GitHub code scanning)."""
from __future__ import annotations

import json
import os
import sys

from .engine import Finding, verdict, worst_severity
from .rules import owasp_for

_USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
_C = {
    "block": "\033[31m", "warn": "\033[33m", "pass": "\033[32m",
    "dim": "\033[2m", "bold": "\033[1m", "reset": "\033[0m",
}


def _c(s: str, key: str) -> str:
    return f"{_C[key]}{s}{_C['reset']}" if _USE_COLOR else s


def to_text(findings: list[Finding], target: str) -> str:
    lines: list[str] = []
    for f in findings:
        mark = _c("BLOCK", "block") if f.severity == "block" else _c("warn ", "warn")
        loc = _c(f"{f.path}:{f.line}", "dim")
        lines.append(f"[{mark}] {f.category:<13} {loc}  {f.description}")
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
    lines.append(f"{_c('verdict', 'bold')}: {banner}  "
                 f"{blocks} blocking · {warns} warnings · {len(findings)} total  "
                 f"({_c(target, 'dim')})")
    return "\n".join(lines)


def to_json(findings: list[Finding], target: str) -> str:
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
    }, indent=2)


_SARIF_LEVEL = {"block": "error", "warn": "warning"}


def to_sarif(findings: list[Finding], version: str = "0.1.0") -> str:
    """SARIF 2.1.0 so GitHub's code-scanning Security tab renders findings inline."""
    rule_ids = sorted({f.rule for f in findings})
    rules = [{
        "id": rid,
        "name": rid,
        "shortDescription": {"text": next(f.description for f in findings if f.rule == rid)},
        "properties": {
            "category": next(f.category for f in findings if f.rule == rid),
            "owasp": owasp_for(next(f.category for f in findings if f.rule == rid)),
        },
    } for rid in rule_ids]
    results = [{
        "ruleId": f.rule,
        "level": _SARIF_LEVEL.get(f.severity, "note"),
        "message": {"text": f.description + (f"  ¦ {f.excerpt}" if f.excerpt else "")},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": f.path},
                "region": {"startLine": max(1, f.line)},
            }
        }],
    } for f in findings]
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "frisk",
                "informationUri": "https://github.com/Thandv/frisk",
                "version": version,
                "rules": rules,
            }},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2)
