"""Fenced code blocks (```) in any non-code file: their bodies are scanned as code."""
from __future__ import annotations

from pathlib import Path

from ..rules import FENCE_RE, is_code
from . import Span


def extract(path: Path, text: str) -> list[Span]:
    if is_code(path, text):
        return []  # a code file is already scanned as code in full (see plain)
    return [Span(m.start(1), m.end(1), "code") for m in FENCE_RE.finditer(text)]
