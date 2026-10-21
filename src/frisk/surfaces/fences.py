"""Fenced code blocks (```) in any non-code file: their bodies are scanned as code."""
from __future__ import annotations

from pathlib import Path

from ..rules import CODE_EXTS, FENCE_RE
from . import Span


def extract(path: Path, text: str) -> list[Span]:
    if path.suffix.lower() in CODE_EXTS:
        return []  # a code file is already scanned as code in full (see plain)
    return [Span(m.start(1), m.end(1), "code") for m in FENCE_RE.finditer(text)]
