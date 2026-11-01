"""Resolve a scan *target* into local files the engine can read.

A target may be:
  - a local file or directory               -> scanned in place
  - a git URL (https://… .git, git@…, github.com/owner/repo) -> shallow-cloned to a temp dir
  - an MCP config file (claude_desktop_config.json / .mcp.json / .claude.json)
        -> every referenced server is resolved; local ones and npx/uvx/pipx packages
           already in the local cache are scanned; remote ones and uncached packages are
           reported as unverifiable (frisk never fetches).
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

from . import pkgcache
from .debug import log as _root_log, ms_since
from .rules import CODE_EXTS

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
                "uvx": "pypi", "pipx": "pypi", "pip": "pypi"}
# Commands that run a script named in their args (a version suffix is ignored: python3.12).
# Only for these is an arg the server's source; any other command's args are its data.
_INTERPRETERS = {"python", "node", "bun", "deno", "ruby", "bash", "sh"}
_PROJECT_MARKERS = ("pyproject.toml", "package.json", ".git")
_WALK_UP_LEVELS = 3
# Options that take a value, so the value is not mistaken for the subcommand, script or package.
_UV_VALUE_FLAGS = {"--directory", "--project", "--from", "--with", "--with-editable", "--with-requirements",
                   "--python", "-p", "--package", "--env-file", "--index", "--index-url", "--extra-index-url"}
_NPX_VALUE_FLAGS = {"-p", "--package", "-c", "--call", "--registry", "--cache", "--userconfig", "--prefix"}
_PIPX_VALUE_FLAGS = {"--spec", "--python", "--pip-args", "--index-url"}
_UNRESOLVED = "could not resolve a local source to scan"
_RELATIVE = "relative path and no absolute 'cwd' in the config: cannot tell which file runs"
_NOT_CACHED = "not in local cache; frisk does not download"


@dataclass
class ServerRef:
    name: str
    kind: str          # "local" | "package-cached" | "package" | "remote" | "unknown"
    ref: str           # local path, package name, or URL; print it only through display_ref
    scannable: bool
    detail: str = ""
    # A package-cached server (ref is the cached package's own source): the package as the
    # config names it, the cached version, and its declared dependencies, which are not scanned.
    package: str = ""
    version: str = ""
    unscanned_deps: tuple[str, ...] = ()


def display_ref(s: ServerRef) -> str:
    """The server's ref as it may be printed. Every audit output (text, --json, --sarif, -q)
    shows a ref only through this function, and so must any later output of server
    locations (project labels, cache paths; both are built with the same home_label).

    A URL (any remote ref, or a ref containing '://') keeps its scheme, host, port and
    path; userinfo, query and fragment, where tokens live, are dropped, and a URL without a
    scheme and host shows as '<unparsable URL>'. Any other ref is shown with $HOME as ~.
    Env values and headers are never read into a ServerRef, so they cannot reach the output.
    """
    if s.kind == "remote" or "://" in s.ref:
        return _safe_url(s.ref)
    return home_label(s.ref)


def home_label(path: str) -> str:
    """A path as printed: a $HOME prefix is shown as ~."""
    home = str(Path.home()).rstrip(os.sep)
    if path == home:
        return "~"
    return "~" + path[len(home):] if path.startswith(home + os.sep) else path


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
    """How the server really launches. Paths resolve against the spec's absolute 'cwd',
    never against frisk's own working directory."""
    url = spec.get("url") or spec.get("serverUrl")
    if url:
        return ServerRef(name, "remote", url, scannable=False,
                         detail="remote HTTP/SSE server — behavior not statically verifiable")
    cmd = (spec.get("command") or "").strip()
    args = [str(a) for a in spec.get("args") or []]
    cwd = _cwd(spec)
    base = os.path.basename(cmd)
    if base == "uv":
        return _classify_uv(name, args, cwd)
    if base in ("npx", "uvx", "pipx"):
        return _cached_package(name, base, _package_spec(base, args) or cmd)
    if base in _PKG_RUNNERS:
        pkg = next((a for a in args if not a.startswith("-")), "")
        return _package(name, _PKG_RUNNERS[base], pkg or cmd)
    if base.rstrip("0123456789.") in _INTERPRETERS:
        root, why = _first_script(args, cwd)
        if root is None and not why:
            root = _first_existing(args, cwd)
        if root is None:
            return ServerRef(name, "unknown", cmd, scannable=False, detail=why or _UNRESOLVED)
        return _local(name, root, f"local source via {base}")
    exe = _resolve(cmd, cwd) if "/" in cmd or cmd.startswith("~") else None
    if exe is not None and os.path.isfile(exe):
        return ServerRef(name, "local", str(exe), scannable=True, detail="local executable/script")
    why = _RELATIVE if exe is None and "/" in cmd else _UNRESOLVED
    return ServerRef(name, "unknown", cmd or "?", scannable=False, detail=why)


def _classify_uv(name: str, args: list[str], cwd: Path | None) -> ServerRef:
    """`uv run` is local source: rooted at --directory/--project, else the script's project,
    else 'cwd'. `uv tool run` runs a PyPI package, like uvx."""
    opts, rest = _leading_options(args, _UV_VALUE_FLAGS)
    if rest[:2] == ["tool", "run"]:
        return _cached_package(name, "uvx", _package_spec("uvx", rest[2:]) or "uv")
    if rest[:1] != ["run"]:
        return ServerRef(name, "unknown", "uv", scannable=False, detail=_UNRESOLVED)
    run_opts, command = _leading_options(rest[1:], _UV_VALUE_FLAGS)
    project = run_opts.get("--directory") or run_opts.get("--project") \
        or opts.get("--directory") or opts.get("--project")
    if project:
        root = _resolve(project, cwd)
        why = _RELATIVE
    else:
        root, why = _first_script(command, cwd)
        if root is None and cwd is not None:
            root = cwd
    if root is None:
        return ServerRef(name, "unknown", "uv", scannable=False, detail=why or _UNRESOLVED)
    return _local(name, root, "local source via uv")


def _package(name: str, ecosystem: str, pkg: str) -> ServerRef:
    return ServerRef(name, "package", pkg, scannable=False,
                     detail=f"{ecosystem} package — fetch+scan not yet supported (roadmap)")


def _cached_package(name: str, runner: str, spec: str) -> ServerRef:
    """An npx, uvx or pipx server: scannable when one version of its package is in the local
    cache (pinned in the spec, or the only one there). Never downloads; one unusable cache
    entry makes only this server SKIP."""
    pkg, version = _split_spec(runner, spec)
    try:
        copies = [c for c in pkgcache.find(runner, pkg) if c.version == version or not version]
    except pkgcache.CacheError as e:
        return ServerRef(name, "package", spec, scannable=False,
                         detail=f"local cache entry unusable ({e}); frisk does not download")
    versions = sorted({c.version for c in copies})
    if len(versions) > 1:
        return ServerRef(name, "package", spec, scannable=False,
                         detail=f"versions {', '.join(versions)} are cached; frisk cannot tell which one runs")
    if not copies:
        return ServerRef(name, "package", spec, scannable=False, detail=_NOT_CACHED)
    c = copies[0]
    return ServerRef(name, "package-cached", str(c.path), scannable=True,
                     detail=f"{_PKG_RUNNERS[runner]} package {pkg} {c.version} from local cache "
                            f"{home_label(str(c.path))}",
                     package=spec, version=c.version, unscanned_deps=c.deps)


def _package_spec(runner: str, args: list[str]) -> str:
    """The package a runner's args name: npx [-p PKG] PKG, uvx [--from PKG] PKG,
    pipx run [--spec PKG] PKG."""
    if runner == "npx":
        opts, rest = _leading_options(args, _NPX_VALUE_FLAGS)
        return opts.get("--package") or opts.get("-p") or (rest[0] if rest else "")
    if runner == "uvx":
        opts, rest = _leading_options(args, _UV_VALUE_FLAGS)
        return opts.get("--from") or (rest[0] if rest else "")
    _, rest = _leading_options(args, _PIPX_VALUE_FLAGS)
    if rest[:1] != ["run"]:
        return ""
    opts, rest = _leading_options(rest[1:], _PIPX_VALUE_FLAGS)
    return opts.get("--spec") or (rest[0] if rest else "")


def _split_spec(runner: str, spec: str) -> tuple[str, str]:
    """(name, pinned version or ''): npm 'pkg@1.2.3' or '@scope/pkg@1.2.3'; PyPI
    'pkg==1.2.3' or 'pkg@1.2.3', extras dropped. A range or tag is kept as the version, so
    it matches no cached version."""
    if runner == "npx":
        at = spec.find("@", 1)
        return (spec[:at], spec[at + 1:]) if at > 0 else (spec, "")
    name, sep, version = spec.partition("==")
    if not sep:
        name, _, version = spec.partition("@")
    return name.split("[", 1)[0].strip(), version.strip()


def _local(name: str, root: Path, detail: str) -> ServerRef:
    """A scannable local server, unless its root is missing, or is $HOME or above it."""
    if not os.path.exists(root):
        return ServerRef(name, "unknown", str(root), scannable=False, detail=_UNRESOLVED)
    if _at_or_above_home(root):
        return ServerRef(name, "unknown", str(root), scannable=False,
                         detail="source resolves to the home directory or above it; not scanned")
    return ServerRef(name, "local", str(root), scannable=True, detail=detail)


def _leading_options(args: list[str], value_flags: set[str]) -> tuple[dict[str, str], list[str]]:
    """The options before the first positional arg (the value of each flag in `value_flags`),
    and the args from that positional on. A '--' ends the options."""
    opts: dict[str, str] = {}
    i = 0
    while i < len(args) and args[i].startswith("-"):
        if args[i] == "--":
            i += 1
            break
        flag, eq, value = args[i].partition("=")
        if flag in value_flags:
            if not eq:
                i += 1
                value = args[i] if i < len(args) else ""
            opts.setdefault(flag, value)
        i += 1
    return opts, args[i:]


def _cwd(spec: dict) -> Path | None:
    """The spec's working directory if it is absolute (after ~); a relative one is unusable."""
    cwd = spec.get("cwd")
    if not isinstance(cwd, str) or not cwd:
        return None
    path = Path(cwd).expanduser()
    return Path(os.path.normpath(path)) if path.is_absolute() else None


def _resolve(arg: str, cwd: Path | None) -> Path | None:
    """An arg as a path: absolute (after ~) as is, relative against cwd, else None."""
    path = Path(arg).expanduser()
    if not path.is_absolute():
        if cwd is None:
            return None
        path = cwd / path
    return Path(os.path.normpath(path))


def _first_script(args: list[str], cwd: Path | None) -> tuple[Path | None, str]:
    """The first script-like arg decides: (its project root, "") when it is an existing file
    with a code extension or a '#!' start; (None, why) when it is a relative script with no
    cwd, or a named script that does not exist; (None, "") when no arg is script-like."""
    for a in args:
        if a.startswith("-"):
            continue
        named = Path(a).suffix.lower() in CODE_EXTS
        path = _resolve(a, cwd)
        if path is None:
            if named:
                return None, _RELATIVE
            continue
        if os.path.isfile(path) and (named or _has_shebang(path)):
            return _project_root(path), ""
        if named:
            return None, _UNRESOLVED
    return None, ""


def _first_existing(args: list[str], cwd: Path | None) -> Path | None:
    """The first arg that is an existing path: a directory as is, a file by its directory."""
    for a in args:
        path = None if a.startswith("-") else _resolve(a, cwd)
        if path is not None and os.path.exists(path):
            return path.parent if os.path.isfile(path) else path
    return None


def _has_shebang(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            return fh.read(2) == b"#!"
    except OSError as e:
        log.debug("could not read a script candidate error=%s", type(e).__name__)
        return False


def _project_root(script: Path) -> Path:
    """The nearest directory holding pyproject.toml, package.json or .git, from the script's
    own directory up at most _WALK_UP_LEVELS levels, never $HOME or above it; else the
    script's directory (or the script alone when that directory is $HOME or above it)."""
    d = script.parent
    for _ in range(_WALK_UP_LEVELS + 1):
        if _at_or_above_home(d):
            break
        if any(os.path.exists(d / marker) for marker in _PROJECT_MARKERS):
            return d
        d = d.parent
    return script if _at_or_above_home(script.parent) else script.parent


def _at_or_above_home(path: Path) -> bool:
    home = Path.home()
    return path == home or path in home.parents


def parse_mcp_config(path: str | Path) -> list[ServerRef]:
    """Every server in the config: the top-level mcpServers (or servers), then each
    project's mcpServers in a .claude.json, named 'server (project)' with $HOME shown as ~.

    A config whose top level, mcpServers, projects or project entry is not a JSON object
    raises ValueError: frisk cannot tell which servers it holds.
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: the top level is not a JSON object")
    refs = [_classify(name, spec or {}) for name, spec in _servers(data, path).items()]
    for key, project in _object(data, "projects", path).items():
        label = home_label(key)
        if not isinstance(project, dict):
            raise ValueError(f"{path}: project {label} is not a JSON object")
        refs.extend(_classify(f"{name} ({label})", spec or {})
                    for name, spec in _servers(project, f"{path}: project {label}").items())
    return refs


def _servers(obj: dict, where: str | Path) -> dict:
    """The server map: 'mcpServers', else 'servers' (VS Code); {} when neither is set."""
    return _object(obj, "mcpServers" if obj.get("mcpServers") is not None else "servers", where)


def _object(obj: dict, key: str, where: str | Path) -> dict:
    value = obj.get(key)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"{where}: '{key}' is not a JSON object")
    return value


def looks_like_mcp_config(path: str | Path) -> bool:
    p = Path(path)
    if p.name in MCP_CONFIG_NAMES:
        return True
    if p.suffix == ".json" and p.is_file():
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            return isinstance(data, dict) and "mcpServers" in data
        except Exception as e:
            log.debug("not an MCP config (unreadable JSON) error=%s", type(e).__name__)
            return False
    return False
