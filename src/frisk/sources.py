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
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import SplitResult, urlsplit

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


def display_target(target: str) -> str:
    """A scan target as frisk prints and pins it. A URL loses its userinfo, query and
    fragment, so a token in it is never shown or stored; scheme, host, port and path stay,
    so two repositories stay apart. An ssh username (git@) is kept, since ssh needs it and it
    is no secret, but a password beside it is dropped. A URL whose host part cannot be told
    from a password is '<unparsable URL>'. Anything else, a local path, is unchanged."""
    if "://" in target:
        parts = _split_url(target)
        if parts is None:
            return "<unparsable URL>"
        user, _, host = parts.netloc.rpartition("@")
        kept = user.split(":", 1)[0] + "@" if parts.scheme == "ssh" and user else ""
        return f"{parts.scheme}://{kept}{host}{parts.path}"
    user, at, rest = target.partition("@")
    if at and ":" in user and ":" in rest and not os.path.exists(target):  # scp-like 'user:password@host:path'
        return user.split(":", 1)[0] + "@" + rest
    return target


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
                if display_target(target) != target.strip():  # git's message could echo the credential
                    raise RuntimeError(f"git clone failed with exit code {r.returncode} (git's message is not "
                                       f"shown: the URL may carry credentials)")
                raise RuntimeError(f"git clone failed: {r.stderr.strip()[:200]}")
            yield Path(tmp), target
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    else:
        p = Path(target)
        if not p.exists():
            raise FileNotFoundError(f"not a path or recognizable git URL: {display_target(target)}")
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
_WRAPPER_MAX_BYTES = 4096  # a generated console-script wrapper or bin shim is a few hundred bytes
_WALK_UP_LEVELS = 3
# Options that take a value, so the value is not mistaken for the subcommand, script or package.
_UV_VALUE_FLAGS = {"--directory", "--project", "--from", "--with", "--with-editable", "--with-requirements",
                   "--python", "-p", "--package", "--env-file", "--index", "--index-url", "--extra-index-url"}
_NPX_VALUE_FLAGS = {"-p", "--package", "-c", "--call", "--registry", "--cache", "--userconfig", "--prefix"}
_PIPX_VALUE_FLAGS = {"--spec", "--python", "--pip-args", "--index-url"}
_UNRESOLVED = "could not resolve a local source to scan"
_RELATIVE = "relative path and no absolute 'cwd' in the config: cannot tell which file runs"
_NOT_CACHED = "not in local cache; frisk does not download"
# Where parse_mcp_config looks for servers; other config formats are not read.
SERVER_KEYS = "'mcpServers' and 'servers', at the top level and in each 'projects' entry"
# Env variables that make a runtime load code (options, module and library paths, preloads,
# startup files): frisk lock pins their values (as hashes); every other env value may be a
# secret and is never read. Any DYLD_* variable counts too.
CODE_LOADING_ENV = frozenset({
    "NODE_OPTIONS", "NODE_PATH", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME", "LD_PRELOAD", "LD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH", "PERL5OPT", "PERL5LIB", "RUBYOPT",
    "RUBYLIB", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "BASH_ENV", "ENV",
})


@dataclass
class ServerRef:
    name: str
    kind: str          # "local" | "package-cached" | "package" | "wrapper" | "remote" | "unknown" | "invalid"
    ref: str           # local path, package name, or URL; print it only through display_ref
    scannable: bool
    detail: str = ""
    # A package-cached server (ref is the cached package's own source): the package as the
    # config names it, the cached version, and its declared dependencies, which are not scanned.
    package: str = ""
    version: str = ""
    unscanned_deps: tuple[str, ...] = ()
    # sha256 of how the server is started, for frisk lock (see _launch_digest); never printed.
    launch: str = ""
    # A remote URL the entry names beside its command: the command is what gets classified and
    # scanned; the URL is not scanned and is shown only through display_url.
    url: str = ""
    # sha256 of the value of each code-loading env variable the entry sets (CODE_LOADING_ENV),
    # for frisk lock; never the value itself, never printed.
    code_env: dict[str, str] = field(default_factory=dict)


def display_ref(s: ServerRef) -> str:
    """The server's ref as it may be printed. Every audit output (text, --json, --sarif, -q)
    shows a ref only through this function, and so must any later output of server
    locations (project labels, cache paths; both are built with the same home_label).

    A URL (any remote ref, or a ref containing '://') is shown by its scheme, host and port
    only (display_url): its path, parameters, query, fragment and credentials, where access
    keys live, are never printed. A server frisk does not scan whose ref holds whitespace (a whole
    command line pasted into 'command', whose arguments may carry a token) shows only its
    first word and ' …'. Any other ref is shown with $HOME as ~. Env values and headers are
    never read into a ServerRef, so they cannot reach the output.
    """
    if s.kind == "remote" or "://" in s.ref:
        return display_url(s.ref)
    if not s.scannable and len(s.ref.split()) > 1:
        return home_label(s.ref.split()[0]) + " …"
    return home_label(s.ref)


def home_label(path: str) -> str:
    """A path as printed: a $HOME prefix is shown as ~."""
    home = str(Path.home()).rstrip(os.sep)
    if path == home:
        return "~"
    return "~" + path[len(home):] if path.startswith(home + os.sep) else path


def display_url(url: str) -> str:
    """A URL as every output prints it: 'scheme://host[:port]', plus '/…' when a path,
    parameters (';jsessionid=…'), query or fragment followed, none of which is shown (some
    providers put the access key in the path). '<unparsable URL>' when the host part cannot
    be told from a password, or holds anything but a host name or address."""
    parts = _split_url(url)
    host = parts.netloc.rpartition("@")[2] if parts is not None else ""
    if parts is None or not all(ch.isalnum() or ch in "-._:[]" for ch in host):
        return "<unparsable URL>"
    elided = parts.path.strip("/") or parts.query or parts.fragment
    return f"{parts.scheme}://{host}" + ("/…" if elided else "")


def _split_url(url: str) -> SplitResult | None:
    """The URL's parts, or None when its host part cannot be told from a password: no
    scheme or host, a port that is not a number, or an '@' outside the host part (an
    unencoded '#', '?' or '/' in a password has cut the host part short)."""
    try:
        parts = urlsplit(url)
        _ = parts.port  # raises ValueError for a port that is not a number, such as 'user:pass' cut short
    except ValueError:  # also an unclosed IPv6 bracket
        return None
    if not parts.scheme or not parts.netloc.rpartition("@")[2] or ("@" in url and "@" not in parts.netloc):
        return None
    return parts


def _classify(name: str, spec: object, project: Path | None = None) -> ServerRef:
    """How the server really launches. Paths resolve against the spec's 'cwd', else the
    directory of the .claude.json project the server belongs to (Claude Code starts it
    there), never against frisk's own working directory. An entry frisk cannot read is
    'invalid' and affects no other server. An entry with a command and a url is classified
    by its command (a client that reads the command runs it) and keeps the url, which the
    audit reports as not scanned: neither side is dropped."""
    problem = _invalid(spec)
    if problem or not isinstance(spec, dict):  # isinstance only narrows the type
        return ServerRef(name, "invalid", "?", scannable=False, detail=problem)
    url = spec.get("url") or spec.get("serverUrl") or ""
    cmd = (spec.get("command") or "").strip()
    if url and not cmd:
        return ServerRef(name, "remote", url, scannable=False,
                         detail="remote HTTP/SSE server — behavior not statically verifiable")
    ref = _classify_command(name, spec, cmd, project)
    ref.url = url
    return ref


def _classify_command(name: str, spec: dict, cmd: str, project: Path | None) -> ServerRef:
    args = [str(a) for a in spec.get("args") or []]
    cwd = _cwd(spec, project)
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
        runs = _wrapped_package(exe)
        if runs:  # the wrapper is read by the audit, but the code that runs is the package's
            return ServerRef(name, "wrapper", str(exe), scannable=False,
                             detail=f"console-script wrapper or bin shim for {runs}, which frisk does not scan")
        return ServerRef(name, "local", str(exe), scannable=True, detail="local executable/script")
    why = _RELATIVE if exe is None and "/" in cmd else _UNRESOLVED
    return ServerRef(name, "unknown", cmd or "?", scannable=False, detail=why)


def _invalid(spec: object) -> str:
    """Why a server entry is not one frisk can classify, or ''."""
    if not isinstance(spec, dict):
        return "server entry is not a JSON object"
    for key, kind, what in (("command", str, "a string"), ("url", str, "a string"), ("serverUrl", str, "a string"),
                            ("cwd", str, "a string"), ("args", list, "a list")):
        if spec.get(key) is not None and not isinstance(spec[key], kind):
            return f"server entry's '{key}' is not {what}"
    if not (spec.get("command") or spec.get("url") or spec.get("serverUrl")):
        return "server entry has neither a command nor a url"
    return ""


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


def _cwd(spec: dict, project: Path | None) -> Path | None:
    """The directory the server starts in: the spec's 'cwd' (after ~; a relative one is
    taken from the project directory), else the project directory; None when unknown."""
    cwd = spec.get("cwd")
    if not isinstance(cwd, str) or not cwd:
        return project
    return _resolve(cwd, project)


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


def _wrapped_package(exe: Path) -> str:
    """What a console-script wrapper or bin shim at `exe` runs, or '' when it is not one:
    a file inside a node package (an npm bin link resolves there); a small Python script
    that imports a name from a package and calls that name in sys.exit(...), as pip, pipx
    and uv generate; or a small shell shim that execs node (pnpm, cmd-shim)."""
    real = Path(os.path.realpath(exe))
    parts = real.parts
    if "node_modules" in parts:
        i = len(parts) - 1 - parts[::-1].index("node_modules")
        package = "/".join(parts[i + 1:i + 3] if parts[i + 1].startswith("@") else parts[i + 1:i + 2])
        if package != ".bin" and i + 2 < len(parts):
            return f"the node package '{package}'"
    try:
        with real.open("rb") as fh:
            head = fh.read(_WRAPPER_MAX_BYTES + 1)
    except OSError as e:
        log.debug("could not read a command error=%s", type(e).__name__)
        return ""
    if len(head) > _WRAPPER_MAX_BYTES or not head.startswith(b"#!"):
        return ""
    shebang, _, body = head.decode("utf-8", "replace").partition("\n")
    if "python" in shebang:
        for line in body.splitlines():
            words = line.split()  # 'from M import F' (or 'F as G'): a generated wrapper calls it
            if (len(words) in (4, 6) and words[0] == "from" and words[2] == "import" and words[1] != "__future__"
                    and f"sys.exit({words[-1]}(" in body):
                return f"the Python package '{words[1].split('.')[0]}'"
    elif "sh" in shebang and ("exec node " in body or 'exec "$basedir/node"' in body):
        return "a node package"
    return ""


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
    """Whether `path` really is $HOME or a directory above it: both sides are compared with
    symlinks resolved, so a link to $HOME, or $HOME reached through a link, still counts."""
    real, home = Path(os.path.realpath(path)), Path(os.path.realpath(Path.home()))
    return real == home or real in home.parents


def parse_mcp_config(path: str | Path) -> list[ServerRef]:
    """Every server in the config: the top-level mcpServers and servers, then each
    project's mcpServers in a .claude.json, named 'server (project)' with $HOME shown as ~.

    A config whose top level, mcpServers, projects or project entry is not a JSON object
    raises ValueError: frisk cannot tell which servers it holds.
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: the top level is not a JSON object")
    refs = [_server(name, spec) for name, spec in _servers(data, path).items()]
    for key, project in _object(data, "projects", path).items():
        label = home_label(key)
        if not isinstance(project, dict):
            raise ValueError(f"{path}: project {label} is not a JSON object")
        directory = Path(key).expanduser()
        base = Path(os.path.normpath(directory)) if directory.is_absolute() else None
        refs.extend(_server(f"{name} ({label})", spec, base)
                    for name, spec in _servers(project, f"{path}: project {label}").items())
    return refs


def _server(name: str, spec: object, project: Path | None = None) -> ServerRef:
    ref = _classify(name, spec, project)
    ref.launch = _launch_digest(spec)
    ref.code_env = _code_env(spec)
    return ref


def _code_env(spec: object) -> dict[str, str]:
    env = spec.get("env") if isinstance(spec, dict) else None
    if not isinstance(env, dict):
        return {}
    return {name: hashlib.sha256(json.dumps(value, default=str).encode("utf-8")).hexdigest()
            for name, value in env.items() if name in CODE_LOADING_ENV or name.startswith("DYLD_")}


def _launch_digest(spec: object) -> str:
    """sha256 of how a server is started: command, args, cwd, type, its URL without
    credentials, query or fragment (the path counts: a changed endpoint is a change), and the
    NAMES of its env vars and headers. Their values are left out, so rotating a secret is not
    a change (a URL frisk cannot split is hashed whole)."""
    shape: object = spec
    if isinstance(spec, dict):
        url = spec.get("url") or spec.get("serverUrl")
        parts = _split_url(url) if isinstance(url, str) else None
        launch = {key: spec.get(key) for key in ("command", "args", "cwd", "type")}
        launch["url"] = f"{parts.scheme}://{parts.netloc.rpartition('@')[2]}{parts.path}" if parts else url
        for key in ("env", "headers"):
            value = spec.get(key)
            launch[key] = sorted(value) if isinstance(value, dict) else type(value).__name__
        shape = launch
    return hashlib.sha256(json.dumps(shape, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def _servers(obj: dict, where: str | Path) -> dict:
    """Every server in 'mcpServers' and in 'servers': Claude Code reads the first, VS Code the
    second, so a config holding both is audited whole and neither map can hide the other. A
    'servers' name already taken is suffixed ' (servers)' (again if need be), never dropped."""
    servers = dict(_object(obj, "mcpServers", where))
    for name, spec in _object(obj, "servers", where).items():
        while name in servers:
            name += " (servers)"
        servers[name] = spec
    return servers


def _object(obj: dict, key: str, where: str | Path) -> dict:
    value = obj.get(key)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"{where}: '{key}' is not a JSON object")
    return value


def split_configs(targets: list[str], configs: list[str]) -> tuple[list[str], list[str]]:
    """(the targets that are not MCP config files, every MCP config to audit per server).

    A target that is an MCP config file joins the configs, ahead of the --mcp-config ones,
    so it is audited even when another target directory also holds it (that directory's
    scan reads it as a plain file). Each config file is kept once.
    """
    named = [t for t in targets if os.path.isfile(t) and looks_like_mcp_config(t)]
    is_named = set(named)
    return [t for t in targets if t not in is_named], _each_config_once(named + configs)


def _each_config_once(paths: list[str]) -> list[str]:
    """Config paths in the order given, each file once: spellings that resolve to the same
    file (relative, absolute, through a symlink) count as one."""
    seen: set[str] = set()
    unique: list[str] = []
    for p in paths:
        key = os.path.realpath(p)
        if key not in seen:
            seen.add(key)
            unique.append(p)
    return unique


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
