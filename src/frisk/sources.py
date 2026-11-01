"""Resolve a scan *target* into local files the engine can read.

A target may be:
  - a local file or directory               -> scanned in place
  - a git URL (https://… .git, git@…, github.com/owner/repo) -> shallow-cloned to a temp dir
  - an MCP config file (claude_desktop_config.json / .mcp.json / .claude.json)
        -> every referenced server is resolved; local ones are scanned, remote/
           package ones are reported as unverifiable (cannot scan without fetching).
"""
from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from .debug import log as _root_log, ms_since

log = _root_log.getChild("sources")

_GIT_URL = re.compile(r"^(https?://[^\s]+?(\.git)?|git@[^\s]+:[^\s]+|github\.com/[^\s/]+/[^\s/]+)$",
                      re.IGNORECASE)


def is_git_url(s: str) -> bool:
    if Path(s).exists():
        return False
    return bool(_GIT_URL.match(s.strip())) or s.startswith(("https://github.com/",
                                                            "https://gitlab.com/"))


def _normalize_git(url: str) -> str:
    url = url.strip()
    if url.startswith("github.com/"):
        return "https://" + url
    return url


@contextlib.contextmanager
def materialize(target: str):
    """Yield (root_path: Path, label: str) for scanning; clean up clones afterward."""
    if is_git_url(target):
        tmp = tempfile.mkdtemp(prefix="frisk-")
        try:
            t0 = time.monotonic()
            # The URL is not logged: it can carry credentials.
            log.debug("git clone start args=6")
            try:
                r = subprocess.run(
                    ["git", "clone", "--depth", "1", "--quiet", _normalize_git(target), tmp],
                    capture_output=True, text=True, timeout=120,
                )
            except Exception as e:
                log.debug("git clone end status=error error=%s ms=%d", type(e).__name__, ms_since(t0))
                raise
            log.debug("git clone end status=exit rc=%d ms=%d", r.returncode, ms_since(t0))
            if r.returncode != 0:
                raise RuntimeError(f"git clone failed: {r.stderr.strip()[:200]}")
            yield Path(tmp), target
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    else:
        p = Path(target)
        if not p.exists():
            raise FileNotFoundError(f"not a path or recognizable git URL: {target}")
        yield p, target


# --- MCP config parsing -----------------------------------------------------

MCP_CONFIG_NAMES = {
    "claude_desktop_config.json", ".mcp.json", ".claude.json", "mcp.json",
}
_PKG_RUNNERS = {"npx": "npm", "npm": "npm", "pnpm": "npm", "bunx": "npm",
                "uvx": "pypi", "uv": "pypi", "pipx": "pypi", "pip": "pypi"}
_INTERPRETERS = {"python", "python3", "node", "bun", "deno", "ruby", "bash", "sh"}


@dataclass
class ServerRef:
    name: str
    kind: str          # "local" | "package" | "remote" | "unknown"
    ref: str           # local path, package name, or URL; print it only through display_ref
    scannable: bool
    detail: str = ""


def display_ref(s: ServerRef) -> str:
    """The server's ref as it may be printed. Every audit output (text, --json, --sarif, -q)
    shows a ref only through this function, and so must any later output of server
    locations (project labels, cache paths).

    A URL (any remote ref, or a ref containing '://') keeps its scheme, host, port and
    path; userinfo, query and fragment, where tokens live, are dropped, and a URL without a
    scheme and host shows as '<unparsable URL>'. Env values and headers are never read into
    a ServerRef, so they cannot reach the output.
    """
    if s.kind == "remote" or "://" in s.ref:
        return _safe_url(s.ref)
    return s.ref


def _safe_url(url: str) -> str:
    try:
        parts = urlsplit(url)
    except ValueError:  # for example an unclosed IPv6 bracket
        return "<unparsable URL>"
    host = parts.netloc.rpartition("@")[2]
    if not parts.scheme or not host:
        return "<unparsable URL>"
    return f"{parts.scheme}://{host}{parts.path}"


def _classify(name: str, spec: dict) -> ServerRef:
    url = spec.get("url") or spec.get("serverUrl")
    if url:
        return ServerRef(name, "remote", url, scannable=False,
                         detail="remote HTTP/SSE server — behavior not statically verifiable")
    cmd = (spec.get("command") or "").strip()
    args = [str(a) for a in spec.get("args", [])]
    base = os.path.basename(cmd)
    if base in _PKG_RUNNERS:
        pkg = next((a for a in args if not a.startswith("-")), "")
        return ServerRef(name, "package", pkg or cmd, scannable=False,
                         detail=f"{_PKG_RUNNERS[base]} package — fetch+scan not yet supported (roadmap)")
    # interpreter running a local script: scan that script's directory
    for a in args:
        cand = Path(a).expanduser()
        if cand.exists():
            root = cand.parent if cand.is_file() else cand
            return ServerRef(name, "local", str(root), scannable=True,
                             detail=f"local source via {base or 'command'}")
    if cmd and Path(cmd).expanduser().exists():
        return ServerRef(name, "local", str(Path(cmd).expanduser()), scannable=True,
                         detail="local executable/script")
    return ServerRef(name, "unknown", cmd or "?", scannable=False,
                     detail="could not resolve a local source to scan")


def parse_mcp_config(path: str | Path) -> list[ServerRef]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    servers = data.get("mcpServers") or data.get("servers") or {}
    return [_classify(name, spec or {}) for name, spec in servers.items()]


def looks_like_mcp_config(path: str | Path) -> bool:
    p = Path(path)
    if p.name in MCP_CONFIG_NAMES:
        return True
    if p.suffix == ".json" and p.is_file():
        try:
            return "mcpServers" in json.loads(p.read_text(encoding="utf-8"))
        except Exception as e:
            log.debug("not an MCP config (unreadable JSON) error=%s", type(e).__name__)
            return False
    return False
