"""frisk MCP server — lets an agent vet a tool/skill/server BEFORE it installs or runs it.

Stdio JSON-RPC, stdlib only. Add to an MCP client:

  { "mcpServers": { "frisk": { "command": "frisk-mcp" } } }

Tools:
  scan_text(text)        — vet a raw string (e.g. a tool description) for injection/poisoning
  scan_artifact(source)  — vet a local path or git URL (any agent content)
  vet_mcp_server(repo)   — vet an MCP server repo/path before adding it

A malformed request gets a JSON-RPC error and the server keeps serving: -32700 for a line
that is not JSON (or not UTF-8), -32600 for a request that is not an object or whose
method, params or arguments have the wrong type, -32601 for an unknown method, -32602 for
an unknown tool, and -32603 when handling a request fails unexpectedly. A tool that cannot
do its job (a missing path, a failed clone, a bad argument) answers with an isError result.
"""
from __future__ import annotations

import io
import json
import os
import sys
import time
from typing import Callable
from collections import Counter
from pathlib import Path

from . import __version__
from .engine import ScanLimits, ScanResult, counts, scan_target, scan_text, verdict, worst_severity
from .rules import owasp_for
from .debug import log as _root_log, ms_since, setup_debug
from .sources import display_target, is_git_url

log = _root_log.getChild("mcp")

# The protocol versions frisk-mcp speaks, oldest first: initialize answers with the
# client's version when it is one of these, else with the newest.
PROTOCOLS = ("2024-11-05", "2025-03-26", "2025-06-18")
PARSE_ERROR, INVALID_REQUEST, METHOD_NOT_FOUND, INVALID_PARAMS, INTERNAL_ERROR = -32700, -32600, -32601, -32602, -32603
# What a tool raises when it cannot do its job (as for the CLI, where these exit 2): the
# agent gets an isError result. Anything else is a fault in frisk: an INTERNAL_ERROR.
TOOL_ERRORS = (OSError, RuntimeError, ValueError, TypeError)
# An agent's path scan is bounded, so one call cannot hold the server for hours: it stops at
# 20,000 files, 200 MiB read or 30 s, and returns what it found with degraded: true.
MCP_LIMITS = ScanLimits(max_files=20_000, max_bytes=200 * 1024 * 1024, deadline_s=30.0)


def _summary(result: ScanResult, source: str) -> str:
    """The JSON a tool returns: verdict, counts, the first findings (no excerpts: an agent
    never gets the scanned text back) and advice; plus degraded: true and what was not
    scanned when coverage is incomplete."""
    findings = result.findings
    top = sorted(findings, key=lambda f: 0 if f.severity == "block" else 1)[:12]
    payload: dict[str, object] = {
        "source": source,
        "verdict": verdict(findings),
        "worst_severity": worst_severity(findings),
        "counts": counts(findings),
        "findings": [
            {"severity": f.severity, "category": f.category, "rule": f.rule,
             "where": f"{f.path}:{f.line}", "description": f.description,
             "owasp": owasp_for(f.category)}
            for f in top
        ],
        "advice": _advice(verdict(findings)),
    }
    if any(f.category == "coverage" for f in findings):
        payload["degraded"] = True
        payload["coverage"] = {"files_scanned": result.coverage.files_scanned,
                               "skipped": dict(Counter(s.reason for s in result.coverage.skipped))}
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
    _check_scope(source)
    return _summary(scan_target(source, MCP_LIMITS), display_target(source))


def _check_scope(source: str) -> None:
    """Refuse (ValueError: an isError result) a source this server may not scan: a git URL
    under FRISK_MCP_NO_NETWORK=1, before git runs; a path outside FRISK_MCP_ROOTS (an
    os.pathsep list), compared with symlinks and '..' resolved; and '/', $HOME itself and
    /System, unless named in FRISK_MCP_ROOTS."""
    if is_git_url(source):
        if os.environ.get("FRISK_MCP_NO_NETWORK") == "1":
            raise ValueError("refused: git URLs are not scanned here (FRISK_MCP_NO_NETWORK=1)")
        return
    real = Path(os.path.realpath(source))
    roots = [Path(os.path.realpath(r)) for r in os.environ.get("FRISK_MCP_ROOTS", "").split(os.pathsep) if r]
    if real in roots:
        return
    if roots and not any(root in real.parents for root in roots):
        raise ValueError(f"refused: {source} is outside FRISK_MCP_ROOTS")
    if real in (Path("/"), Path(os.path.realpath(Path.home())), Path("/System")):
        raise ValueError(f"refused: {source} is too broad to scan; name it in FRISK_MCP_ROOTS to allow it")


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


def _tools_list() -> list[dict[str, object]]:
    return [{"name": n, "description": d,
             "inputSchema": {"type": "object", "properties": props, "required": req}}
            for n, (_, d, props, req) in TOOLS.items()]


def _error(rid: object, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}


def handle(req: object) -> dict | None:
    """The response to one request (None for a notification). Raises only on a fault in
    frisk itself, which main() answers with INTERNAL_ERROR."""
    if not isinstance(req, dict):
        return _error(None, INVALID_REQUEST, "invalid request: not a JSON object")
    m = req.get("method")
    rid = req.get("id")
    params = req.get("params", {})
    if not isinstance(m, str):
        return _error(rid, INVALID_REQUEST, "invalid request: method is not a string")
    if not isinstance(params, dict):
        return _error(rid, INVALID_REQUEST, "invalid request: params is not an object")
    if m == "initialize":
        asked = params.get("protocolVersion")
        return {"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": asked if asked in PROTOCOLS else PROTOCOLS[-1],
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "frisk", "version": __version__}}}
    if m == "ping":
        return {"jsonrpc": "2.0", "id": rid, "result": {}}
    if m == "tools/list":
        return {"jsonrpc": "2.0", "id": rid, "result": {"tools": _tools_list()}}
    if m == "tools/call":
        return _call(rid, params)
    if m.startswith("notifications/"):
        return None
    return _error(rid, METHOD_NOT_FOUND, f"method not found: {m}")


def _call(rid: object, params: dict) -> dict:
    name, args = params.get("name"), params.get("arguments", {})
    if not isinstance(args, dict):
        return _error(rid, INVALID_REQUEST, "invalid request: arguments is not an object")
    if not isinstance(name, str) or name not in TOOLS:
        return _error(rid, INVALID_PARAMS, f"unknown tool: {name!r}")
    t0 = time.monotonic()
    try:
        tool: Callable[..., object] = TOOLS[name][0]
        text = str(tool(**args))
    except TOOL_ERRORS as e:
        log.debug("tool end name=%s status=error error=%s ms=%d", name, type(e).__name__, ms_since(t0))
        return {"jsonrpc": "2.0", "id": rid,
                "result": {"content": [{"type": "text", "text": f"error: {e}"}],
                           "isError": True}}
    log.debug("tool end name=%s status=ok ms=%d bytes=%d", name, ms_since(t0), len(text))
    return {"jsonrpc": "2.0", "id": rid,
            "result": {"content": [{"type": "text", "text": text}]}}


def _respond(line: str) -> dict | None:
    """The response to one input line: a parse error, handle()'s answer, or INTERNAL_ERROR
    when handle() fails, so one request can never end the loop."""
    try:
        line.encode("utf-8")  # bytes that were not UTF-8 arrive as lone surrogates
        req = json.loads(line)
    except (ValueError, RecursionError) as e:  # not UTF-8, not JSON, or nested too deep
        log.debug("request not parsed error=%s", type(e).__name__)
        return _error(None, PARSE_ERROR, "parse error")
    try:
        return handle(req)
    except Exception as e:  # noqa: BLE001 - a fault in frisk answers this request, the loop goes on
        log.debug("request failed error=%s", type(e).__name__)
        return _error(req.get("id") if isinstance(req, dict) else None, INTERNAL_ERROR,
                      f"internal error ({type(e).__name__})")


def main() -> None:
    setup_debug()
    if isinstance(sys.stdin, io.TextIOWrapper):
        sys.stdin.reconfigure(errors="surrogateescape")  # an undecodable byte is a parse error, not a crash
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        resp = _respond(line)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
