"""frisk — vet AI-agent content (MCP servers, skills, plugins) before you install it."""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__
from .engine import ScanResult, coverage_warning, display_prefix, reroot, scan_path, scan_text, verdict, fails
from .report import AuditRecord, audit_text, printable, to_text, to_json, to_sarif, _c
from .sources import display_ref, is_git_url, materialize, parse_mcp_config, split_configs
from . import pin, proxy
from .debug import setup_debug


def _scan_target(target: str) -> ScanResult:
    """Scan one target; paths follow docs/adr/0001-finding-paths.md."""
    with materialize(target) as (root, _label):
        result = scan_path(root)
        if is_git_url(target):
            return reroot(result, "", "git")  # clone-relative
        return reroot(result, display_prefix(target, root.is_file()), "local")


def _distinct(targets: list[str]) -> list[str]:
    """Targets in order, without repeats.

    A local path named twice (any spelling; a directory compared by real path, a file by
    its directory's real path plus its own name, as the directory walk sees it, so two
    names for one file both count) is scanned once. An
    existing target inside another target directory is dropped only when that
    directory's scan already covers it: no .git component between them (scan_path skips
    .git directories) and, since real paths are compared, a target reached through a
    symlinked directory never counts as inside. Case-insensitive filesystems are not
    folded: 'skill' and 'Skill' are scanned twice.
    """
    def real(t: str) -> str:
        # A file is identified by its real directory plus its own name: the parent's walk
        # reads a symlinked file under the link's name, so it is inside that directory.
        if os.path.isfile(t):
            return os.path.join(os.path.realpath(os.path.dirname(os.path.abspath(t))), os.path.basename(t))
        return os.path.realpath(t)

    local = {t: real(t) for t in targets if not is_git_url(t)}
    dirs = {r for t, r in local.items() if os.path.isdir(t)}
    existing = {t for t in local if os.path.exists(t)}  # a missing target still errors

    def covered(path: str) -> bool:
        for d in dirs:
            if d != path and path.startswith(d.rstrip(os.sep) + os.sep):
                parts = Path(os.path.relpath(path, d)).parts
                if parts[-1] == ".git" and os.path.isfile(path):
                    parts = parts[:-1]  # a gitfile is scanned by the parent's walk
                if ".git" not in parts:
                    return True
        return False

    seen: set[str] = set()
    out: list[str] = []
    for t in targets:
        key = local.get(t, t)
        if key in seen or (t in existing and covered(key)):
            continue
        seen.add(key)
        out.append(t)
    return out


def _audit_config(path: str) -> list[AuditRecord]:
    """One record per server in the config, in config order; [] when it lists none.

    A server frisk does not scan (remote, an uncached package, an unresolved or invalid
    entry) carries a coverage.unscanned warning at 'name::<its ref>', so no audit with a
    skipped server is ever PASS.
    """
    records: list[AuditRecord] = []
    for s in parse_mcp_config(path):
        if s.scannable:
            server = reroot(scan_path(s.ref), f"{s.name}::", "mcp")
            records.append(AuditRecord(s, server, verdict(server.findings)))
        else:
            note = coverage_warning(display_ref(s), "coverage.unscanned", f"MCP server not scanned ({s.kind})")
            records.append(AuditRecord(s, reroot(note, f"{s.name}::", "mcp"), None))
    return records


# --- scan (default) ---------------------------------------------------------

def _cmd_scan(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        prog="frisk",
        description="Static, zero-execution security scanner for AI-agent content "
                    "(MCP servers, Claude Code skills/plugins/subagents, Cursor rules). "
                    "Subcommands: lock, verify.",
    )
    p.add_argument("targets", nargs="*",
                   help="local paths and/or git URLs to scan; an MCP config file is audited as with --mcp-config")
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

    result = ScanResult()
    audits: list[str] = []
    servers: list[AuditRecord] = []
    label = ", ".join(args.targets + args.mcp_config) or "<text>"
    try:
        if args.text is not None:
            result.extend(scan_text(args.text, "<text>"))
        # A config named as a target is audited, never text-scanned: its env values must not show.
        targets, configs = split_configs(args.targets, args.mcp_config)
        for t in _distinct(targets):
            result.extend(_scan_target(t))
        for cfg in configs:
            records = _audit_config(cfg)
            for rec in records:
                result.extend(rec.result)
            servers.extend(records)
            audits.append(audit_text(cfg, records))
    except (OSError, RuntimeError, ValueError) as e:  # an input frisk cannot read: exit 2
        print(f"frisk: {printable(str(e))}", file=sys.stderr)
        return 2
    findings = result.sort().findings

    if args.json:
        print(to_json(result, label, servers if configs else None))
    elif args.sarif:
        print(to_sarif(result, __version__))
    elif args.quiet:
        print(f"frisk: {verdict(findings)}  ({printable(label)})")
    else:
        if audits:
            print("\n".join(audits))
            print()
        print(to_text(result, label, show_coverage=bool(args.targets or args.mcp_config)))

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
    except (OSError, RuntimeError, ValueError) as e:  # an input frisk cannot read: exit 2
        print(f"frisk lock: {printable(str(e))}", file=sys.stderr)
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
    except (OSError, RuntimeError, ValueError) as e:  # an input frisk cannot read: exit 2
        print(f"frisk verify: {printable(str(e))}", file=sys.stderr)
        return 2

    if args.json:
        import json
        print(json.dumps(report, indent=2))
    else:
        for r in report:
            entry = printable(r["entry"])
            if r["status"] == "ok":
                print(f"  [{_c('ok   ', 'pass')}] {entry}")
            elif r["status"] == "error":
                print(f"  [{_c('error', 'warn')}] {entry}  {printable(r.get('detail', ''))}")
            else:
                print(f"  [{_c('DRIFT', 'block')}] {entry}")
                if r.get("launch"):
                    print(_c("           ~ changed: how it starts (command, args, cwd, URL, env or header names)",
                             "block"))
                for f in r.get("changed", []):
                    print(_c(f"           ~ changed: {printable(f)}", "block"))
                for f in r.get("added", []):
                    print(_c(f"           + added:   {printable(f)}", "warn"))
                for f in r.get("removed", []):
                    print(_c(f"           - removed: {printable(f)}", "warn"))
        drift = sum(1 for r in report if r["status"] != "ok")
        v = _c("DRIFT DETECTED", "block") if pin.has_drift(report) else _c("no drift", "pass")
        print(f"\nverify: {v}  ({drift} of {len(report)} entries changed)")
    return 1 if pin.has_drift(report) else 0


def _cmd_proxy(argv: list[str]) -> int:
    if "--" not in argv:
        print("frisk proxy: usage: frisk proxy [--log FILE] -- <server command>\n"
              "  e.g.  frisk proxy -- uvx some-mcp-server", file=sys.stderr)
        return 2
    sep = argv.index("--")
    opts, server_cmd = argv[:sep], argv[sep + 1:]
    if not server_cmd:
        print("frisk proxy: no server command after --", file=sys.stderr)
        return 2
    p = argparse.ArgumentParser(prog="frisk proxy",
                                description="Enforce frisk checks at runtime between an MCP client and server.")
    p.add_argument("--log", metavar="FILE", help="append proxy events to a file (default: stderr)")
    args = p.parse_args(opts)
    logf = open(args.log, "a", encoding="utf-8") if args.log else sys.stderr
    try:
        return proxy.Proxy(server_cmd, log=logf).run()
    except FileNotFoundError as e:
        print(f"frisk proxy: cannot launch server: {e}", file=sys.stderr)
        return 2


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    setup_debug()
    if argv and argv[0] == "lock":
        return _cmd_lock(argv[1:])
    if argv and argv[0] == "verify":
        return _cmd_verify(argv[1:])
    if argv and argv[0] == "proxy":
        return _cmd_proxy(argv[1:])
    return _cmd_scan(argv)


if __name__ == "__main__":
    raise SystemExit(main())
