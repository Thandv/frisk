"""frisk MCP server — lets an agent vet a tool/skill/server BEFORE it installs or runs it.

Stdio JSON-RPC, stdlib only. Add to an MCP client:

  { "mcpServers": { "frisk": { "command": "frisk-mcp" } } }

Tools:
  scan_text(text)        — vet a raw string (e.g. a tool description) for injection/poisoning
  scan_artifact(source)  — vet a local path or git URL (any agent content)
  vet_mcp_server(repo)   — vet an MCP server repo/path before adding it
"""
from __future__ import annotations

import json
import sys

from . import __version__
from .engine import scan_path, scan_text, verdict, worst_severity
from .rules import owasp_for
from .sources import materialize

PROTOCOL = "2024-11-05"


def _summary(findings, source: str) -> str:
    blocks = sum(1 for f in findings if f.severity == "block")
    warns = sum(1 for f in findings if f.severity == "warn")
    top = sorted(findings, key=lambda f: 0 if f.severity == "block" else 1)[:12]
    payload = {
        "source": source,
        "verdict": verdict(findings),
        "worst_severity": worst_severity(findings),
        "counts": {"block": blocks, "warn": warns, "total": len(findings)},
        "findings": [
            {"severity": f.severity, "category": f.category, "rule": f.rule,
             "where": f"{f.path}:{f.line}", "description": f.description,
             "owasp": owasp_for(f.category)}
            for f in top
        ],
        "advice": _advice(verdict(findings)),
    }
    return json.dumps(payload, indent=2)


def _advice(v: str) -> str:
    return {
        "BLOCK": "DO NOT install or run this. It contains high-severity patterns "
                 "(code execution, secret exfiltration, destructive ops, or hidden "
                 "instructions). Show the findings to the user.",
        "WARN": "Review before installing. Findings warrant a human look; proceed "
                "only if each warning is expected for this tool's stated purpose.",
        "PASS": "No known-malicious patterns found. Static scan only — not a guarantee; "
                "remote/package behavior is not covered.",
    }[v]


def _scan_source(source: str) -> str:
    with materialize(source) as (root, _):
        findings = scan_path(root, root if root.is_dir() else None)
    return _summary(findings, source)


TOOLS = {
    "scan_text": (
        lambda text: _summary(scan_text(text, "<text>"), "<text>"),
        "Vet a raw string (e.g. an MCP tool description, skill body, or prompt) for "
        "prompt-injection, tool-poisoning, and hidden/invisible-unicode instructions.",
        {"text": {"type": "string"}}, ["text"],
    ),
    "scan_artifact": (
        lambda source: _scan_source(source),
        "Vet AI-agent content at a local path or git URL (skill, plugin, subagent, "
        "ruleset) for code-execution, secret exfiltration, destructive ops, and injection.",
        {"source": {"type": "string"}}, ["source"],
    ),
    "vet_mcp_server": (
        lambda repo: _scan_source(repo),
        "Vet an MCP server (git URL or local path) BEFORE adding it to your config. "
        "Returns a PASS/WARN/BLOCK verdict and findings.",
        {"repo": {"type": "string"}}, ["repo"],
    ),
}


def _tools_list():
    return [{"name": n, "description": d,
             "inputSchema": {"type": "object", "properties": props, "required": req}}
            for n, (_, d, props, req) in TOOLS.items()]


def handle(req: dict):
    m = req.get("method"); rid = req.get("id")
    if m == "initialize":
        return {"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": PROTOCOL,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "frisk", "version": __version__}}}
    if m == "tools/list":
        return {"jsonrpc": "2.0", "id": rid, "result": {"tools": _tools_list()}}
    if m == "tools/call":
        p = req.get("params", {})
        name = p.get("name"); args = p.get("arguments", {})
        try:
            text = str(TOOLS[name][0](**args))
            return {"jsonrpc": "2.0", "id": rid,
                    "result": {"content": [{"type": "text", "text": text}]}}
        except Exception as e:  # noqa: BLE001
            return {"jsonrpc": "2.0", "id": rid,
                    "result": {"content": [{"type": "text", "text": f"error: {e}"}],
                               "isError": True}}
    if m and m.startswith("notifications/"):
        return None
    return {"jsonrpc": "2.0", "id": rid,
            "error": {"code": -32601, "message": f"method not found: {m}"}}


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue
        resp = handle(req)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
