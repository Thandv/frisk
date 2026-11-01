"""Shell commands in build files: Makefile recipes, Dockerfile RUN instructions and justfile
recipes are scanned as code, each command with its backslash-continued lines."""
from __future__ import annotations

import re
from pathlib import Path

from . import Span

# One command: the rest of the line plus every backslash-continued line after it (group 1).
_CMD = r"((?:[^\n]*\\\n)*[^\n]*)"
# Makefile: a tab-prefixed recipe line, or a recipe after ';' on a rule line (target: deps ; cmd).
_MAKE = re.compile(r"^\t" + _CMD + r"|^[^\s#][^\n:=]*:[^\n=;]*;" + _CMD, re.MULTILINE)
_DOCKER = re.compile(r"^[ \t]*RUN[ \t]+" + _CMD, re.MULTILINE | re.IGNORECASE)
_JUST = re.compile(r"^[ \t]+" + _CMD, re.MULTILINE)  # justfile recipe bodies are indented


def _kind(name: str) -> re.Pattern | None:
    lower = name.lower()
    if lower in ("makefile", "gnumakefile") or lower.endswith(".mk"):
        return _MAKE
    if lower == "dockerfile" or lower.startswith("dockerfile.") or lower.endswith(".dockerfile"):
        return _DOCKER
    if lower in ("justfile", ".justfile"):
        return _JUST
    return None


def extract(path: Path, text: str) -> list[Span]:
    rx = _kind(path.name)
    if rx is None:
        return []
    spans = []
    for m in rx.finditer(text):
        group = 1 if m.group(1) is not None else 2
        spans.append(Span(m.start(group), m.end(group), "code"))
    return spans
