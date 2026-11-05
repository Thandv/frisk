"""frisk — vet AI-agent content (MCP servers, skills, plugins) before you install it."""
from __future__ import annotations

import argparse
import codecs
import contextlib
import json
import os
import sys
from pathlib import Path

from . import __version__
from .engine import (MAX_FILE_BYTES, ScanLimits, ScanResult, coverage_warning, display_prefix, reroot, scan_path,
                     scan_target, scan_text, verdict, fails)
from .report import AuditRecord, audit_text, colorize, printable, to_text, to_json, to_sarif
from .sources import (SERVER_KEYS, display_ref, display_target, display_url, home_label, is_git_url,
                      parse_mcp_config, split_configs)
from . import pin, proxy
from .debug import setup_debug


def _shown(target: str, result: ScanResult) -> ScanResult:
    """A target's scan with the paths shown; they follow docs/adr/0001-finding-paths.md."""
    if is_git_url(target):
        return reroot(result, "", "git")  # clone-relative
    return reroot(result, display_prefix(target, Path(target).is_file()), "local")


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


def _audit_config(path: str, limits: ScanLimits | None = None) -> list[AuditRecord]:
    """One record per server in the config, in config order; [] when it lists none.

    A server frisk does not scan (remote, an uncached package, an unresolved or invalid
    entry) carries a coverage.unscanned warning at 'name::<its ref>', so no audit with a
    skipped server is ever PASS, and its record has no verdict. A wrapper is read, though
    the package it runs is not: when the wrapper's own file has findings, the record has
    the verdict of all its findings (WARN or BLOCK). A remote URL an entry names beside its
    command (the command is scanned as usual) also warns, at 'name::<the URL>'.
    """
    records: list[AuditRecord] = []
    for s in parse_mcp_config(path):
        own = ScanResult()  # a wrapper's own file
        # The config (the user's own) names the code that runs: it is read where a link in
        # that path leads, as it runs, not judged as a link out of its directory.
        code = os.path.realpath(s.ref)
        if s.scannable:
            result = scan_path(code, limits=limits)
        else:
            result = coverage_warning(display_ref(s), "coverage.unscanned", f"MCP server not scanned ({s.kind})")
            if s.kind == "wrapper":  # the wrapper itself is read: a payload in it still blocks
                own = scan_path(code, limits=limits)
                result.extend(own)
        if s.url:
            result.extend(coverage_warning(display_url(s.url), "coverage.unscanned",
                                           "MCP server entry also names a remote URL, which is not scanned"))
        server = reroot(result, f"{s.name}::", "mcp")
        records.append(AuditRecord(s, server, verdict(server.findings) if s.scannable or own.findings else None))
    return records


def _scan_stdin(max_bytes: int) -> ScanResult:
    """Scan standard input as text, at most its first `max_bytes` bytes.

    Longer input raises coverage.truncated (a character cut at the limit is left out), so it
    is never PASS; the rest is read to its end and dropped, so a writer never gets a broken
    pipe (Foreman's admission scan drops every finding then). Input that is not UTF-8 is
    scanned with the bad bytes replaced and raises coverage.unreadable.
    """
    stream = getattr(sys.stdin, "buffer", None)
    if stream is None:
        raise ValueError("--stdin: standard input is not readable")
    data = stream.read(max_bytes + 1)
    truncated = len(data) > max_bytes
    data = data[:max_bytes]
    while truncated and stream.read(1 << 16):  # drain, unscanned
        pass
    unreadable = False
    try:
        text = codecs.getincrementaldecoder("utf-8")().decode(data, final=not truncated)
    except UnicodeDecodeError:
        text, unreadable = data.decode("utf-8", errors="replace"), True
    result = scan_text(text.replace("\r\n", "\n").replace("\r", "\n"), "<stdin>", max_chars=max_bytes)
    if unreadable:
        result.extend(coverage_warning("<stdin>", "coverage.unreadable", "standard input is not valid UTF-8 "
                                       "(UnicodeDecodeError); scanned with undecodable bytes replaced"))
    if truncated:
        result.extend(coverage_warning("<stdin>", "coverage.truncated", f"standard input is over the {max_bytes}-byte "
                                       f"limit: only its first {max_bytes} bytes were pattern-matched"))
    return reroot(result, "", "text")


# --- scan (default) ---------------------------------------------------------

def _positive(value: str) -> int:
    n = int(value)
    if n < 1:
        raise argparse.ArgumentTypeError(f"must be a positive number of bytes, not {value}")
    return n


_SCAN_EPILOG = """\
subcommands:
  frisk [options] TARGET ...    scan (this help)
  frisk lock                    pin a content fingerprint of approved content (frisk lock --help)
  frisk verify                  re-check pinned content for drift (frisk verify --help)
  frisk proxy [options] -- CMD  check an MCP server's tools at runtime (frisk proxy: usage)

exit status of a scan:
  0  no finding reached the --fail-on level (always 0 with --fail-on never)
  1  the worst finding reached the --fail-on level (default: block)
  2  a usage error, no target, or a target, MCP config, --stdin or --sarif-out FILE that
     cannot be read or written (a file inside a target that cannot be read is a warning)
frisk lock exits 0, or 2 on an error. frisk verify exits 0, 1 on drift or an entry it could
not verify, 2 on a lockfile it cannot read. frisk proxy exits with the server's status, or 2
on a usage error or a server it cannot start.
"""


def _scan_parser() -> argparse.ArgumentParser:
    """The scan's argument parser (`frisk [options] TARGET ...`)."""
    p = argparse.ArgumentParser(
        prog="frisk",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Static, zero-execution security scanner for AI-agent content (MCP servers,\n"
                    "Claude Code skills/plugins/subagents, Cursor rules).",
        epilog=_SCAN_EPILOG,
    )
    p.add_argument("targets", nargs="*",
                   help="local paths and/or git URLs to scan; an MCP config file is audited as with --mcp-config")
    p.add_argument("--mcp-config", action="append", default=[], metavar="FILE",
                   help="audit every server in an MCP config file (repeatable)")
    p.add_argument("--text", metavar="STR", help="scan a raw string instead of a path")
    p.add_argument("--stdin", action="store_true",
                   help="scan text read from standard input: at most --max-file-bytes bytes are scanned, and longer "
                        "input warns (coverage.truncated)")
    p.add_argument("--json", action="store_true", help="emit findings as JSON")
    p.add_argument("--sarif", action="store_true", help="emit SARIF 2.1.0 (GitHub code scanning)")
    p.add_argument("--sarif-out", metavar="FILE",
                   help="also write SARIF 2.1.0 to FILE; the report is printed as usual and the exit code is unchanged")
    p.add_argument("--max-file-bytes", type=_positive, default=MAX_FILE_BYTES, metavar="N",
                   help=f"skip files larger than N bytes (a block finding), and match only the first and last N/2 "
                        f"characters of a longer --text (a warning) (default: {MAX_FILE_BYTES})")
    p.add_argument("--fail-on", choices=["block", "warn", "never"], default="block",
                   help="exit non-zero when the worst finding reaches this level (default: block)")
    p.add_argument("-q", "--quiet", action="store_true", help="print only the verdict line")
    p.add_argument("-V", "--version", action="version", version=f"frisk {__version__}")
    return p


def _scan_label(args: argparse.Namespace) -> str:
    """The report's label: the targets and configs as shown, else <stdin> or <text>."""
    return ", ".join(display_target(t) for t in args.targets + args.mcp_config) or (
        "<stdin>" if args.stdin and args.text is None else "<text>")


def _audit_configs(configs: list[str], limits: ScanLimits, result: ScanResult,
                   servers: list[AuditRecord]) -> list[str]:
    """Audit each config into `result` and `servers`; the audit text of each, in order."""
    audits: list[str] = []
    for cfg in configs:
        records = _audit_config(cfg, limits)
        if not records:  # nothing was audited: never PASS
            where = home_label(cfg)
            note = coverage_warning(where, "coverage.no_servers", f"no MCP servers found in {where} (frisk reads "
                                    f"{SERVER_KEYS})")
            result.extend(reroot(note, "", "mcp"))
        for rec in records:
            result.extend(rec.result)
        servers.extend(records)
        audits.append(audit_text(cfg, records))
    return audits


def _scan_all(args: argparse.Namespace, limits: ScanLimits, result: ScanResult,
              servers: list[AuditRecord]) -> tuple[list[str], list[str]]:
    """Scan --text, --stdin, the targets and the configs into `result`: (configs, audit texts).

    Raises OSError, RuntimeError or ValueError for an input frisk cannot read."""
    if args.text is not None:
        result.extend(scan_text(args.text, "<text>", max_chars=args.max_file_bytes))
    if args.stdin:
        result.extend(_scan_stdin(args.max_file_bytes))
    # A config named as a target is audited, never text-scanned: its env values must not show.
    targets, configs = split_configs(args.targets, args.mcp_config)
    for t in _distinct(targets):
        result.extend(_shown(t, scan_target(t, limits)))
    return configs, _audit_configs(configs, limits, result, servers)


def _print_report(args: argparse.Namespace, result: ScanResult, label: str, servers: list[AuditRecord] | None,
                  audits: list[str]) -> None:
    """Print the report in the format the flags ask for: JSON, SARIF, the verdict line or text."""
    if args.json:
        print(to_json(result, label, servers))
    elif args.sarif:
        print(to_sarif(result, __version__))
    elif args.quiet:
        print(f"frisk: {verdict(result.findings)}  ({printable(label)})")
    else:
        if audits:
            print("\n".join(audits))
            print()
        print(to_text(result, label, show_coverage=bool(args.targets or args.mcp_config)))


def _cmd_scan(argv: list[str]) -> int:
    p = _scan_parser()
    args = p.parse_args(argv)
    if not args.targets and not args.mcp_config and args.text is None and not args.stdin:
        p.print_help()
        return 2

    result = ScanResult()
    servers: list[AuditRecord] = []
    label = _scan_label(args)
    try:
        configs, audits = _scan_all(args, ScanLimits(max_file_bytes=args.max_file_bytes), result, servers)
    except (OSError, RuntimeError, ValueError) as e:  # an input frisk cannot read: exit 2
        print(f"frisk: {printable(str(e))}", file=sys.stderr)
        return 2
    findings = result.sort().findings
    if args.sarif_out:
        try:
            Path(args.sarif_out).write_text(to_sarif(result, __version__) + "\n", encoding="utf-8")
        except OSError as e:
            print(f"frisk: cannot write the SARIF file: {printable(str(e))}", file=sys.stderr)
            return 2
    _print_report(args, result, label, servers if configs else None, audits)
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
    notes: list[str] = []
    try:
        lock = pin.build_lock(args.targets, args.mcp_config, _lock_dir(args.lockfile), notes)
        pin.write_lock(lock, args.lockfile)
    except (OSError, RuntimeError, ValueError) as e:  # an input frisk cannot read: exit 2
        print(f"frisk lock: {printable(str(e))}", file=sys.stderr)
        return 2
    for note in notes:
        print(f"frisk lock: {printable(note)}", file=sys.stderr)
    n = len(lock["entries"])
    print(colorize(f"frisk: pinned {n} entr{'y' if n == 1 else 'ies'} → {args.lockfile}", "pass"))
    return 0


def _lock_dir(lockfile: str) -> Path:
    """The lockfile's directory: local paths in the lock are relative to it."""
    return Path(os.path.abspath(lockfile)).parent


def _cmd_verify(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="frisk verify",
                                description="Re-check pinned content for drift (rug pull / auto-update).")
    p.add_argument("--lockfile", default=pin.LOCK_DEFAULT, help=f"lockfile path (default: {pin.LOCK_DEFAULT})")
    p.add_argument("--json", action="store_true", help="emit the drift report as JSON")
    args = p.parse_args(argv)
    try:
        report = pin.verify_lock(pin.read_lock(args.lockfile), _lock_dir(args.lockfile))
    except (OSError, RuntimeError, ValueError) as e:  # an input frisk cannot read: exit 2
        print(f"frisk verify: {printable(str(e))}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for r in report:
            entry = printable(r["entry"])
            if r["status"] == "ok":
                print(f"  [{colorize('ok   ', 'pass')}] {entry}")
            elif r["status"] == "error":
                print(f"  [{colorize('error', 'warn')}] {entry}  {printable(r.get('detail', ''))}")
            else:
                print(f"  [{colorize('DRIFT', 'block')}] {entry}")
                if r.get("launch"):
                    print(colorize("           ~ changed: how it starts (command, args, cwd, URL, env or header names)",
                             "block"))
                for name in r.get("env", []):
                    print(colorize(f"           ~ {printable(name)} changed", "block"))
                for f in r.get("changed", []):
                    print(colorize(f"           ~ changed: {printable(f)}", "block"))
                for f in r.get("added", []):
                    print(colorize(f"           + added:   {printable(f)}", "warn"))
                for f in r.get("removed", []):
                    print(colorize(f"           - removed: {printable(f)}", "warn"))
        changed, failed = sum(1 for r in report if r["status"] == "DRIFT"), pin.unverified(report)
        could_not = f"could not verify {failed} entr{'y' if failed == 1 else 'ies'}"
        if changed:
            v = colorize("DRIFT DETECTED", "block")
        elif failed:
            v = colorize(could_not, "warn")
        else:
            v = colorize("no drift", "pass")
        also = f"; {could_not}" if changed and failed else ""
        print(f"\nverify: {v}  ({changed} of {len(report)} entries changed{also})")
    return 1 if pin.has_drift(report) or pin.unverified(report) else 0


def _cmd_proxy(argv: list[str]) -> int:
    if "--" not in argv:
        print("frisk proxy: usage: frisk proxy [--log FILE] [--pins FILE | --no-pins] [--on-change flag|drop] "
              "-- <server command>\n"
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
    where = p.add_mutually_exclusive_group()
    where.add_argument("--pins", metavar="FILE", type=Path,
                       help="keep tool pins in FILE across runs (default: $XDG_STATE_HOME/frisk/pins/<sha256 of the "
                            "server command>.json, with ~/.local/state when XDG_STATE_HOME is unset)")
    where.add_argument("--no-pins", action="store_true", help="keep tool pins in memory only; write no pins file")
    p.add_argument("--on-change", choices=proxy.ON_CHANGE, default="flag",
                   help="a tool whose definition changed since it was pinned: flag it (kept, annotated) or drop it "
                        "(default: flag)")
    args = p.parse_args(opts)
    pins = None if args.no_pins else args.pins or proxy.default_pins_file(server_cmd)
    with contextlib.ExitStack() as stack:  # the --log file is closed on every path
        try:
            logf = stack.enter_context(open(args.log, "a", encoding="utf-8")) if args.log else sys.stderr
        except OSError as e:
            print(f"frisk proxy: cannot open the log file: {printable(str(e))}", file=sys.stderr)
            return 2
        try:
            return proxy.Proxy(server_cmd, log=logf, pins_file=pins, on_change=args.on_change).run()
        except proxy.LaunchError as e:  # not found, not executable, ...
            print(f"frisk proxy: cannot launch server: {printable(str(e))}", file=sys.stderr)
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
