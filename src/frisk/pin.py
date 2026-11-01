"""Tool-pinning / rug-pull detection.

The threat: agent content you approved (an MCP server, a skill, a plugin) silently
*changes* afterward — an auto-update or a deliberate "rug pull" that swaps clean
content for malicious. `frisk lock` records a content fingerprint of what you
approved; `frisk verify` recomputes it later and flags any drift.

Static analog of mcp-scan's tool pinning: we pin the *bytes* of the source, so a
changed file, an added script, or a swapped package reference all surface as drift.

An MCP config, named as a target or with --mcp-config, is pinned per server, never as a
whole file: one entry lists its server names, and one entry per server pins how it starts
(sources._launch_digest: no env or header values) plus the code frisk scans for it. So
other changes to the file (Claude Code rewrites .claude.json constantly) are not drift.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from .debug import log as _root_log
from .sources import (ServerRef, display_target, looks_like_mcp_config, materialize, parse_mcp_config,
                      split_configs)

log = _root_log.getChild("pin")

LOCK_DEFAULT = ".frisk-lock.json"
# The one message for an MCP config that an older frisk pinned as a whole file.
RELOCK_WHOLE_CONFIG = "MCP config pinned as a whole file by an older frisk: run frisk lock again to pin each server"


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def fingerprint_path(root: Path) -> dict:
    """Content fingerprint of a file or directory: an overall digest + per-file hashes."""
    if root.is_file():
        h = _sha(root.read_bytes())
        return {"digest": h, "files": {root.name: h}}
    files: dict[str, str] = {}
    overall = hashlib.sha256()
    for p in sorted(p for p in root.rglob("*") if p.is_file() and ".git" not in p.parts):
        rel = str(p.relative_to(root))
        try:
            fh = _sha(p.read_bytes())
        except OSError as e:
            log.debug("fingerprint skipped a file error=%s", type(e).__name__)
            continue
        files[rel] = fh
        overall.update(rel.encode())
        overall.update(fh.encode())
    return {"digest": overall.hexdigest(), "files": files}


def _entry_for_target(target: str) -> dict:
    """The target's content, pinned under its credential-free form (display_target): a token
    in a git URL is used for this clone but never stored; verify re-clones the clean URL,
    and git's own credential helper supplies any auth it needs."""
    clean = display_target(target)
    if clean == "<unparsable URL>":
        raise ValueError("cannot pin a URL whose host part cannot be told from a password")
    with materialize(target) as (root, _):
        fp = fingerprint_path(root)
    fp.update({"kind": "source", "recompute": {"type": "target", "value": clean}})
    return fp


def build_lock(targets: list[str], configs: list[str]) -> dict:
    entries: dict[str, dict] = {}
    targets, configs = split_configs(targets, configs)
    for t in targets:
        entries[display_target(t)] = _entry_for_target(t)
    for cfg in configs:
        servers = parse_mcp_config(cfg)
        entries[cfg] = {"kind": "mcp-config", **_server_names(servers),
                        "recompute": {"type": "config_servers", "config": cfg}}
        for s in servers:
            # re-found through the live config on verify: a changed launch, changed code, a
            # new cached version or a server that is gone is drift.
            entry = {"kind": s.kind, "launch": s.launch, **_server_fingerprint(s),
                     "recompute": {"type": "server", "config": cfg, "name": s.name}}
            if s.kind == "package-cached":
                entry["version"] = s.version
            entries[f"{cfg}::{s.name}"] = entry
    return {"version": 1, "entries": entries}


def _server_names(servers: list[ServerRef]) -> dict:
    names = {s.name: "" for s in servers}  # 'files' are the names: added or removed ones show
    return {"digest": _sha("\0".join(sorted(names)).encode("utf-8", "surrogatepass")), "files": names}


def _server_fingerprint(s: ServerRef) -> dict:
    """How the server starts, the values of its code-loading env variables (as hashes) and
    the code frisk scans for it (none when it scans none)."""
    if s.kind == "package-cached":
        code = _cached_fingerprint(s)
    elif s.scannable:
        code = fingerprint_path(Path(s.ref))
    else:
        code = {"digest": "", "files": {}}
    parts = [s.launch, code["digest"]]
    if not s.code_env:  # the digest of a server without code-loading env variables is unchanged
        return {"digest": _sha("\0".join(parts).encode()), "files": code["files"]}
    parts.append(json.dumps(s.code_env, sort_keys=True))
    return {"digest": _sha("\0".join(parts).encode()), "files": code["files"], "code_env": s.code_env}


def _cached_fingerprint(s: ServerRef) -> dict:
    fp = fingerprint_path(Path(s.ref))
    fp["digest"] = _sha(f"{s.version}\0{fp['digest']}".encode())
    return fp


def _ref_digest(s: ServerRef) -> str:
    """The pinned reference: the package as the config names it, else the ref (the same
    string whether or not the package is cached, so a config_ref entry keeps verifying)."""
    return _sha((s.package or s.ref).encode())


def _config(config: str, parsed: dict) -> dict[str, ServerRef]:
    """The config's servers by name (the first of a repeated name), read once per verify,
    however many entries pin it; a config that cannot be read raises again for each entry."""
    if config not in parsed:
        try:
            servers: dict[str, ServerRef] = {}
            for s in parse_mcp_config(config):
                servers.setdefault(s.name, s)
            parsed[config] = servers
        except Exception as e:  # noqa: BLE001 - raised again below, for each entry of the config
            parsed[config] = e
    result = parsed[config]
    if isinstance(result, Exception):
        raise result
    return result


def _recompute(entry: dict, parsed: dict) -> dict:
    rc = entry["recompute"]
    if rc["type"] == "server":
        s = _config(rc["config"], parsed).get(rc["name"])
        if s is None:
            return {"digest": "<missing>", "files": {}}
        return {**_server_fingerprint(s), "launch": s.launch}
    if rc["type"] == "config_servers":
        return _server_names(list(_config(rc["config"], parsed).values()))
    # The types below are written only by older frisk versions; they still verify.
    if rc["type"] == "target":
        with materialize(rc["value"]) as (root, _):
            return fingerprint_path(root)
    if rc["type"] == "path":
        p = Path(rc["value"])
        if not p.exists():
            return {"digest": "<missing>", "files": {}}
        return fingerprint_path(p)
    if rc["type"] == "config_ref":
        s = _config(rc["config"], parsed).get(rc["name"])
        return {"digest": _ref_digest(s) if s is not None else "<missing>", "files": {}}
    return {"digest": _sha(rc["value"].encode()), "files": {}}


def verify_lock(lock: dict) -> list[dict]:
    """Return a drift report: one record per locked entry with status and changed files.
    Entries are named without credentials, also those an older frisk pinned with a token in
    a git URL (that stored URL is still what gets cloned, so they keep verifying)."""
    out = []
    parsed: dict = {}  # each MCP config is read once, however many entries pin it
    for stored, old in lock.get("entries", {}).items():
        key = display_target(stored)
        try:
            new = _recompute(old, parsed)
        except Exception as e:  # noqa: BLE001
            out.append({"entry": key, "status": "error", "detail": str(e)[:120]})
            continue
        if new["digest"] == old["digest"]:
            out.append({"entry": key, "status": "ok"})
            continue
        if _whole_config(old):
            out.append({"entry": key, "status": "error", "detail": RELOCK_WHOLE_CONFIG})
            continue
        old_f, new_f = old.get("files", {}), new.get("files", {})
        changed = sorted(f for f in new_f if f in old_f and new_f[f] != old_f[f])
        added = sorted(set(new_f) - set(old_f))
        removed = sorted(set(old_f) - set(new_f))
        record = {"entry": key, "status": "DRIFT", "changed": changed, "added": added, "removed": removed}
        if "launch" in old and new.get("launch", old["launch"]) != old["launch"]:
            record["launch"] = "changed"
        old_env, new_env = old.get("code_env", {}), new.get("code_env", {})
        env = sorted(name for name in old_env.keys() | new_env.keys() if old_env.get(name) != new_env.get(name))
        if env:
            record["env"] = env  # the names of the code-loading env variables whose value changed
        out.append(record)
    return out


def _whole_config(entry: dict) -> bool:
    """An entry an older frisk wrote for an MCP config named as a target: the whole file."""
    rc = entry.get("recompute", {})
    value = rc.get("value", "")
    return rc.get("type") == "target" and os.path.isfile(value) and looks_like_mcp_config(value)


def has_drift(report: list[dict]) -> bool:
    return any(r["status"] in ("DRIFT", "error") for r in report)


def write_lock(lock: dict, path: str = LOCK_DEFAULT) -> None:
    Path(path).write_text(json.dumps(lock, indent=2), encoding="utf-8")


def read_lock(path: str = LOCK_DEFAULT) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))
