"""Shared pyproject.toml loader for the test suite (not a test module: no test_ prefix).

Uses tomllib on Python 3.11+. On older interpreters (the 3.9 floor) it falls back to
parse_minimal(), a small reader that understands only what the repo's config tests
need: [table] and [[array-of-tables]] headers, and `key = value` lines whose value is
a string, a boolean, an integer or a (possibly multi-line) list of those. Any other
value (inline tables, dates, ...) is left out of the result rather than guessed at.
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path
from typing import Any

PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"

_ARRAY_HEADER = re.compile(r"^\[\[\s*([^\[\]]+?)\s*\]\]$")
_HEADER = re.compile(r"^\[\s*([^\[\]]+?)\s*\]$")
_KEY = re.compile(r"^([A-Za-z0-9_\-\"]+)\s*=\s*(.*)$")


def _strip_comment(raw: str) -> str:
    """Drop a trailing `# comment` that is not inside a quoted string."""
    quote = ""
    for i, ch in enumerate(raw):
        if quote:
            if ch == quote:
                quote = ""
        elif ch in "\"'":
            quote = ch
        elif ch == "#":
            return raw[:i].strip()
    return raw.strip()


def _open_brackets(raw: str) -> int:
    """Count `[` minus `]` outside quoted strings."""
    depth = 0
    quote = ""
    for ch in raw:
        if quote:
            if ch == quote:
                quote = ""
        elif ch in "\"'":
            quote = ch
        elif ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
    return depth


def _literal(raw: str) -> tuple[bool, Any]:
    """Parse one TOML value as a Python literal; return (ok, value)."""
    if raw in ("true", "false"):
        return True, raw == "true"
    try:
        return True, ast.literal_eval(raw)
    except (ValueError, SyntaxError):
        return False, None


def _table(root: dict[str, Any], dotted: str, array: bool) -> dict[str, Any]:
    """Return (creating as needed) the table named by a dotted header."""
    node = root
    parts = [p.strip().strip('"') for p in dotted.split(".")]
    for part in parts[:-1]:
        child = node.setdefault(part, {})
        node = child[-1] if isinstance(child, list) else child
    if array:
        entry: dict[str, Any] = {}
        node.setdefault(parts[-1], []).append(entry)
        return entry
    table: dict[str, Any] = node.setdefault(parts[-1], {})
    return table


def parse_minimal(text: str) -> dict[str, Any]:
    """Parse the subset of TOML described in the module docstring."""
    root: dict[str, Any] = {}
    current = root
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = _strip_comment(lines[i])
        i += 1
        if not line:
            continue
        array_header = _ARRAY_HEADER.match(line)
        if array_header:
            current = _table(root, array_header.group(1), array=True)
            continue
        header = _HEADER.match(line)
        if header:
            current = _table(root, header.group(1), array=False)
            continue
        key = _KEY.match(line)
        if not key:
            continue
        raw = key.group(2)
        # A list may span lines: keep appending lines until its brackets close.
        while _open_brackets(raw) > 0 and i < len(lines):
            raw += "\n" + _strip_comment(lines[i])
            i += 1
        ok, value = _literal(raw)
        if ok:
            current[key.group(1).strip('"')] = value
    return root


def load_pyproject(path: Path = PYPROJECT) -> dict[str, Any]:
    """Return the parsed pyproject.toml (tomllib on 3.11+, parse_minimal before)."""
    if sys.version_info >= (3, 11):
        import tomllib  # stdlib only from 3.11; the 3.9 floor uses parse_minimal

        with path.open("rb") as fh:
            return tomllib.load(fh)
    return parse_minimal(path.read_text(encoding="utf-8"))
