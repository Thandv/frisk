"""package.json "scripts": each script value is a shell command and is scanned as code.

The file is parsed as data only (json.loads). A malformed package.json raises here, so the
engine reports it as a coverage.surface_error and the rest of the file is still text-scanned.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from . import Span

_STRING = re.compile(r'"(?:[^"\\]|\\.)*"', re.DOTALL)
_COLON = re.compile(r"\s*:\s*")


def extract(path: Path, text: str) -> list[Span]:
    if path.name != "package.json":
        return []
    data = json.loads(text)
    scripts = data.get("scripts") if isinstance(data, dict) else None
    if not isinstance(scripts, dict):
        return []
    # Outside strings JSON has no quotes, so string literals tokenize in order; a key is a
    # literal followed by ':', and its value literal is the next one.
    literals = list(_STRING.finditer(text))
    spans = []
    for key, value in zip(literals, literals[1:]):
        if (_COLON.fullmatch(text, key.end(), value.start())
                and scripts.get(json.loads(key.group())) == json.loads(value.group())):
            spans.append(Span(value.start() + 1, value.end() - 1, "code"))
    return spans
