"""frisk — vet AI-agent content (MCP servers, skills, plugins) before you install it."""
from __future__ import annotations

import argparse
import sys

from . import __version__
from .engine import Finding, scan_path, scan_text, verdict, fails
from .report import to_text, to_json, to_sarif, _c
from .sources import materialize, parse_mcp_config
from . import pin


def _scan_target(target: str) -> list[Finding]:
    with materialize(target) as (root, _label):
        return scan_path(root, root if root.is_dir() else None)


def _audit_config(path: str) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    lines: list[str] = [_c(f"MCP config audit: {path}", "bold"), ""]
    servers = parse_mcp_config(path)
    if not servers:
        lines.append("  (no servers found in config)")
        return findings, lines
    for s in servers:
        if s.scannable:
            fs = scan_path(s.ref)
            for f in fs:
                f.path = f"{s.name}::{f.path}"
            findings.extend(fs)
            v = verdict(fs)
            tag = _c(f"{v:<5}", {"PASS": "pass", "WARN": "warn", "BLOCK": "block"}[v])
        else:
            tag = _c("SKIP ", "dim")
        lines.append(f"  [{tag}] {s.name:<22} {_c(s.kind, 'dim')}  {s.detail}")
        if not s.scannable:
            lines.append(_c(f"           → {s.ref}", "dim"))
    return findings, lines


# --- scan (default) ---------------------------------------------------------

def _cmd_scan(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        prog="frisk",
        description="Static, zero-execution security scanner for AI-agent content "
                    "(MCP servers, Claude Code skills/plugins/subagents, Cursor rules). "
                    "Subcommands: lock, verify.",
    )
    p.add_argument("targets", nargs="*", help="local paths and/or git URLs to scan")
    p.add_argument("--mcp-config", action="append", default=[], metavar="FILE",
                   help="audit every server in an MCP config file (repeatable)")
    p.add_argument("--text", metavar="STR", help="scan a raw string instead of a path")
    p.add_argument("--json", action="store_true", help="emit findings as JSON")
    p.add_argument("--sarif", action="store_true", help="emit SARIF 2.1.0 (GitHub code scanning)")
    p.add_argument("--fail-on", choices=["block", "warn", "never"], default="block",
                   help="exit non-zero when the worst finding reaches this level (default: block)")
    p.add_argument("-q", "--quiet", action="store_true", help="print only the verdict line")
    p.add_argument("-V", "--version", action="version", version=f"frisk {__version__}")
    args = p.parse_args(argv)

    if not args.targets and not args.mcp_config and args.text is None:
        p.print_help()
        return 2

    findings: list[Finding] = []
    audit_lines: list[str] = []
    label = ", ".join(args.targets + args.mcp_config) or "<text>"
    try:
        if args.text is not None:
            findings.extend(scan_text(args.text, "<text>"))
        for t in args.targets:
            findings.extend(_scan_target(t))
        for cfg in args.mcp_config:
            fs, lines = _audit_config(cfg)
            findings.extend(fs)
            audit_lines.extend(lines)
    except (FileNotFoundError, RuntimeError, ValueError) as e:
        print(f"frisk: {e}", file=sys.stderr)
        return 2

    if args.json:
        print(to_json(findings, label))
    elif args.sarif:
        print(to_sarif(findings, __version__))
    elif args.quiet:
        print(f"frisk: {verdict(findings)}  ({label})")
    else:
        if audit_lines:
            print("\n".join(audit_lines)); print()
        print(to_text(findings, label))

    if args.fail_on == "never":
        return 0
    return 1 if fails(findings, args.fail_on) else 0


# --- lock / verify (rug-pull detection) -------------------------------------

def _cmd_lock(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="frisk lock",
                                description="Pin a content fingerprint of approved agent content.")
    p.add_argument("targets", nargs="*", help="local paths and/or git URLs to pin")
    p.add_argument("--mcp-config", action="append", default=[], metavar="FILE",
                   help="pin every server referenced by an MCP config (repeatable)")
    p.add_argument("--lockfile", default=pin.LOCK_DEFAULT, help=f"lockfile path (default: {pin.LOCK_DEFAULT})")
    args = p.parse_args(argv)
    if not args.targets and not args.mcp_config:
        print("frisk lock: nothing to pin (give targets or --mcp-config)", file=sys.stderr)
        return 2
    try:
        lock = pin.build_lock(args.targets, args.mcp_config)
        pin.write_lock(lock, args.lockfile)
    except (FileNotFoundError, RuntimeError, ValueError) as e:
        print(f"frisk lock: {e}", file=sys.stderr)
        return 2
    n = len(lock["entries"])
    print(_c(f"frisk: pinned {n} entr{'y' if n == 1 else 'ies'} → {args.lockfile}", "pass"))
    return 0


def _cmd_verify(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="frisk verify",
                                description="Re-check pinned content for drift (rug pull / auto-update).")
    p.add_argument("--lockfile", default=pin.LOCK_DEFAULT, help=f"lockfile path (default: {pin.LOCK_DEFAULT})")
    p.add_argument("--json", action="store_true", help="emit the drift report as JSON")
    args = p.parse_args(argv)
    try:
        report = pin.verify_lock(pin.read_lock(args.lockfile))
    except (FileNotFoundError, RuntimeError, ValueError) as e:
        print(f"frisk verify: {e}", file=sys.stderr)
        return 2

    if args.json:
        import json
        print(json.dumps(report, indent=2))
    else:
        for r in report:
            if r["status"] == "ok":
                print(f"  [{_c('ok   ', 'pass')}] {r['entry']}")
            elif r["status"] == "error":
                print(f"  [{_c('error', 'warn')}] {r['entry']}  {r.get('detail','')}")
            else:
                print(f"  [{_c('DRIFT', 'block')}] {r['entry']}")
                for f in r.get("changed", []):
                    print(_c(f"           ~ changed: {f}", "block"))
                for f in r.get("added", []):
                    print(_c(f"           + added:   {f}", "warn"))
                for f in r.get("removed", []):
                    print(_c(f"           - removed: {f}", "warn"))
        drift = sum(1 for r in report if r["status"] != "ok")
        v = _c("DRIFT DETECTED", "block") if pin.has_drift(report) else _c("no drift", "pass")
        print(f"\nverify: {v}  ({drift} of {len(report)} entries changed)")
    return 1 if pin.has_drift(report) else 0


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "lock":
        return _cmd_lock(argv[1:])
    if argv and argv[0] == "verify":
        return _cmd_verify(argv[1:])
    return _cmd_scan(argv)


if __name__ == "__main__":
    raise SystemExit(main())
