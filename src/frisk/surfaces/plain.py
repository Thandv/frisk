"""The whole file: code files (by extension or shebang) get the code and text rules, every other file the text rules."""
from __future__ import annotations

from pathlib import Path

from ..rules import is_code
from . import Span


def extract(path: Path, text: str) -> list[Span]:
    whole = len(text)
    if is_code(path, text):
        return [Span(0, whole, "code"), Span(0, whole, "text")]
    return [Span(0, whole, "text")]
