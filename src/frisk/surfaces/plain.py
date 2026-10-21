"""The whole file: code files get the code and text rules, every other file the text rules."""
from __future__ import annotations

from pathlib import Path

from ..rules import CODE_EXTS
from . import Span


def extract(path: Path, text: str) -> list[Span]:
    whole = len(text)
    if path.suffix.lower() in CODE_EXTS:
        return [Span(0, whole, "code"), Span(0, whole, "text")]
    return [Span(0, whole, "text")]
