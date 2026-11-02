"""Find a package in the local npx, uv and pipx caches, offline.

frisk never downloads and never runs npm, npx, uv or pip: this module only lists
directories and reads package.json, METADATA and RECORD files, and it imports no process
or network module. Cache roots, each overridable by an env var:

  npx       $FRISK_NPX_CACHE   or ~/.npm/_npx              <hash>/node_modules/<pkg>
  uv tools  $FRISK_UV_TOOLS    or ~/.local/share/uv/tools  <pkg>/lib/python*/site-packages
  uv cache  $FRISK_UV_CACHE    or ~/.cache/uv              archive-v0/*/lib/python*/site-packages
  pipx      $FRISK_PIPX_VENVS  or ~/.local/pipx/venvs      <pkg>/lib/python*/site-packages
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import NamedTuple

_ROOTS = {
    "npx": ("FRISK_NPX_CACHE", ".npm/_npx"),
    "uv-tools": ("FRISK_UV_TOOLS", ".local/share/uv/tools"),
    "uv-cache": ("FRISK_UV_CACHE", ".cache/uv"),
    "pipx": ("FRISK_PIPX_VENVS", ".local/pipx/venvs"),
}
_NAME_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")


class Cached(NamedTuple):
    """One cached copy of a package: its own source (a directory, or one module file), its
    version and the names of its declared dependencies (not part of `path`)."""
    path: Path
    version: str
    deps: tuple[str, ...]


class CacheError(Exception):
    """A cache entry for the package exists but cannot be used: unreadable, malformed, or
    leading outside its cache root."""


def find(runner: str, name: str) -> list[Cached]:
    """Every cached copy of package `name` for runner npx, uvx or pipx, in a fixed order.

    A name that is not a plain registry name (a path, URL or git spec) is never found.
    """
    try:
        if runner == "npx":
            return _npx(name) if _npm_name(name) else []
        if not _python_name(name):
            return []
        if runner == "uvx":
            tools = _root("uv-tools")
            archive = _root("uv-cache") / "archive-v0"
            envs = [(env, tools) for env in _env_dirs(tools, name)]
            envs += [(env, archive) for env in (sorted(archive.iterdir()) if archive.is_dir() else [])]
            return _python(envs, name)
        venvs = _root("pipx")
        return _python([(env, venvs) for env in _env_dirs(venvs, name)], name)
    except OSError as e:
        raise CacheError(type(e).__name__) from e


def _root(which: str) -> Path:
    var, default = _ROOTS[which]
    return Path(os.environ.get(var) or Path.home() / default)


def _npx(name: str) -> list[Cached]:
    root = _root("npx")
    out: list[Cached] = []
    for entry in sorted(root.iterdir()) if root.is_dir() else []:
        pkg = entry / "node_modules" / name
        if not os.path.isdir(pkg):
            continue
        requested = _json(entry / "package.json").get("dependencies", {})
        if not isinstance(requested, dict):
            raise CacheError("package.json: dependencies is not an object")
        if name not in requested:
            continue  # a dependency of another package npx ran, not one it was asked to run
        _inside(pkg, root)
        meta = _json(pkg / "package.json")
        version, deps = meta.get("version"), meta.get("dependencies", {})
        if not isinstance(version, str) or not isinstance(deps, dict):
            raise CacheError("package.json: no version, or dependencies is not an object")
        out.append(Cached(pkg, version, tuple(sorted(deps))))
    return out


def _env_dirs(root: Path, name: str) -> list[Path]:
    """The tool environment named after the package, as given and normalised."""
    return [root / n for n in dict.fromkeys((name, _normalise(name))) if os.path.isdir(root / n)]


def _python(envs: list[tuple[Path, Path]], name: str) -> list[Cached]:
    want = _normalise(name)
    out: list[Cached] = []
    for env, root in envs:
        for site in sorted(env.glob("lib/python*/site-packages")):
            for info in sorted(site.glob("*.dist-info")):
                dist, _, version = info.name[:-len(".dist-info")].partition("-")
                if _normalise(dist) != want:
                    continue
                source = _dist_source(site, info)
                _inside(source, root)
                out.append(Cached(source, version, _requires(info / "METADATA")))
    return out


def _dist_source(site: Path, info: Path) -> Path:
    """The distribution's one top-level package or module, from its RECORD.

    A file it installs into the environment's bin/ is either the wrapper an installer
    generates for one of its entry points (pip and uv drop a wheel script of the same name),
    or a wheel's own script, which uvx and pipx run as a command and which is not part of
    that package: frisk does not scan it, so the distribution is unusable.
    """
    tops = set()
    entry_points = None
    for line in _read(info / "RECORD").splitlines():
        parts = line.split(",", 1)[0].split("/")
        if parts[0] == ".." and parts[-2:-1] == ["bin"]:
            entry_points = _entry_points(info) if entry_points is None else entry_points
            if parts[-1] not in entry_points:
                raise CacheError(f"{info.name}: installs a script that is not one of its entry points")
        top = parts[0]
        if top and not top.startswith("..") and top != "__pycache__" and not top.endswith((".dist-info", ".data")):
            tops.add(top)
    if len(tops) != 1 or next(iter(tops)).endswith(".pth"):
        raise CacheError(f"{info.name}: its code is not one package directory or module")
    return site / tops.pop()


def _entry_points(info: Path) -> set[str]:
    """The console and GUI script names in the distribution's entry_points.txt."""
    names: set[str] = set()
    if not os.path.isfile(info / "entry_points.txt"):
        return names
    section = ""
    for line in _read(info / "entry_points.txt").splitlines():
        line = line.strip()
        if line.startswith("["):
            section = line.strip("[]").strip()
        elif section in ("console_scripts", "gui_scripts") and "=" in line:
            names.add(line.split("=", 1)[0].strip())
    return names


def _requires(metadata: Path) -> tuple[str, ...]:
    """Names in Requires-Dist headers, leaving out those only an extra pulls in."""
    names = set()
    for line in _read(metadata).splitlines():
        if not line:
            break  # end of the headers
        if line.startswith("Requires-Dist:"):
            requirement, _, marker = line[len("Requires-Dist:"):].partition(";")
            if "extra" not in marker:
                spec = requirement.strip()
                names.add(spec[:next((i for i, c in enumerate(spec) if c not in _NAME_CHARS), len(spec))])
    names.discard("")
    return tuple(sorted(names))


def _json(path: Path) -> dict:
    try:
        data = json.loads(_read(path))
    except ValueError as e:
        raise CacheError(f"{path.name}: {type(e).__name__}") from e
    if not isinstance(data, dict):
        raise CacheError(f"{path.name}: not a JSON object")
    return data


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        raise CacheError(f"{path.name}: {type(e).__name__}") from e


def _inside(path: Path, root: Path) -> None:
    real, top = os.path.realpath(path), os.path.realpath(root)
    if not real.startswith(top.rstrip(os.sep) + os.sep):
        raise CacheError("the cache entry leads outside the cache")


def _normalise(name: str) -> str:
    """PEP 503: lowercase, with runs of '-', '_' and '.' as one '-'."""
    return "-".join(part for part in name.lower().replace("_", "-").replace(".", "-").split("-") if part)


def _npm_name(name: str) -> bool:
    """A registry name: 'pkg' or '@scope/pkg', no path parts."""
    parts = name.split("/")
    return (len(parts) == 1 or (len(parts) == 2 and parts[0].startswith("@"))) and all(
        p not in ("", ".", "..", "@") and "\\" not in p and not p.startswith(".") for p in parts)


def _python_name(name: str) -> bool:
    return bool(name) and set(name) <= _NAME_CHARS and name[0].isalnum() and name[-1].isalnum()
