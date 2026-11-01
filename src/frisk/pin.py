"""Tool-pinning / rug-pull detection.

The threat: agent content you approved (an MCP server, a skill, a plugin) silently
*changes* afterward — an auto-update or a deliberate "rug pull" that swaps clean
content for malicious. `frisk lock` records a content fingerprint of what you
approved; `frisk verify` recomputes it later and flags any drift.

Static analog of mcp-scan's tool pinning: we pin the *bytes* of the source, so a
changed file, an added script, or a swapped package reference all surface as drift.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .debug import log as _root_log
from .sources import ServerRef, materialize, parse_mcp_config

log = _root_log.getChild("pin")

LOCK_DEFAULT = ".frisk-lock.json"


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
    with materialize(target) as (root, _):
        fp = fingerprint_path(root)
    fp.update({"kind": "source", "recompute": {"type": "target", "value": target}})
    return fp


def build_lock(targets: list[str], configs: list[str]) -> dict:
    entries: dict[str, dict] = {}
    for t in targets:
        entries[t] = _entry_for_target(t)
    for cfg in configs:
        for s in parse_mcp_config(cfg):
            key = f"{cfg}::{s.name}"
            if s.kind == "package-cached":
                # the cached package's content and version, re-found in the cache through
                # the live config on verify: a version change or a missing entry is drift.
                fp = _cached_fingerprint(s)
                fp.update({"kind": s.kind, "version": s.version,
                           "recompute": {"type": "cached_package", "config": cfg, "name": s.name}})
                entries[key] = fp
            elif s.scannable:
                fp = fingerprint_path(Path(s.ref))
                fp.update({"kind": "source",
                           "recompute": {"type": "path", "value": s.ref}})
                entries[key] = fp
            else:
                # package/remote: pin the reference itself, re-read from the live
                # config on verify so a swapped version/URL surfaces as drift.
                entries[key] = {"kind": s.kind, "digest": _ref_digest(s),
                                "files": {},
                                "recompute": {"type": "config_ref",
                                              "config": cfg, "name": s.name}}
    return {"version": 1, "entries": entries}


def _cached_fingerprint(s: ServerRef) -> dict:
    fp = fingerprint_path(Path(s.ref))
    fp["digest"] = _sha(f"{s.version}\0{fp['digest']}".encode())
    return fp


def _ref_digest(s: ServerRef) -> str:
    """The pinned reference: the package as the config names it, else the ref (the same
    string whether or not the package is cached, so a config_ref entry keeps verifying)."""
    return _sha((s.package or s.ref).encode())


def _recompute(entry: dict) -> dict:
    rc = entry["recompute"]
    if rc["type"] == "target":
        with materialize(rc["value"]) as (root, _):
            return fingerprint_path(root)
    if rc["type"] == "path":
        p = Path(rc["value"])
        if not p.exists():
            return {"digest": "<missing>", "files": {}}
        return fingerprint_path(p)
    if rc["type"] == "config_ref":
        for s in parse_mcp_config(rc["config"]):
            if s.name == rc["name"]:
                return {"digest": _ref_digest(s), "files": {}}
        return {"digest": "<missing>", "files": {}}
    if rc["type"] == "cached_package":
        for s in parse_mcp_config(rc["config"]):
            if s.name == rc["name"] and s.kind == "package-cached":
                return _cached_fingerprint(s)
        return {"digest": "<missing>", "files": {}}
    return {"digest": _sha(rc["value"].encode()), "files": {}}


def verify_lock(lock: dict) -> list[dict]:
    """Return a drift report: one record per locked entry with status and changed files."""
    out = []
    for key, old in lock.get("entries", {}).items():
        try:
            new = _recompute(old)
        except Exception as e:  # noqa: BLE001
            out.append({"entry": key, "status": "error", "detail": str(e)[:120]})
            continue
        if new["digest"] == old["digest"]:
            out.append({"entry": key, "status": "ok"})
            continue
        old_f, new_f = old.get("files", {}), new.get("files", {})
        changed = sorted(f for f in new_f if f in old_f and new_f[f] != old_f[f])
        added = sorted(set(new_f) - set(old_f))
        removed = sorted(set(old_f) - set(new_f))
        out.append({"entry": key, "status": "DRIFT",
                    "changed": changed, "added": added, "removed": removed})
    return out


def has_drift(report: list[dict]) -> bool:
    return any(r["status"] in ("DRIFT", "error") for r in report)


def write_lock(lock: dict, path: str = LOCK_DEFAULT) -> None:
    Path(path).write_text(json.dumps(lock, indent=2), encoding="utf-8")


def read_lock(path: str = LOCK_DEFAULT) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))
