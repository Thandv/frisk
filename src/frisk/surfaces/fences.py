"""Fenced code blocks in any non-code, non-markdown file: their bodies are scanned as code.

fence_blocks() is the one fence finder; the markdown surface uses it too.
"""
from __future__ import annotations

import re
from pathlib import Path

from ..rules import MARKDOWN_EXTS, is_code
from . import Span

# An opening fence line: three or more backticks or tildes, at any indent (list items
# indent them), then an info string. A backtick fence's info string has no backtick.
# Backticks after text on the line ("Run: ```sh", also after inline code: "Run `x` ```sh")
# open a fence when only a bare language tag follows them: an agent reads raw text, not the
# rendered page. After a backtick, a space or tab must come before the run: a search that
# started inside a run would rescan the rest of it from every backtick (quadratic).
_OPEN = re.compile(r"(?:^[ \t]*|(?:(?<=[^\s`])[ \t]*|(?<=`)[ \t]+)(?=`{3,}[\w+.-]*$))(`{3,}|~{3,})([^\n]*)$",
                   re.MULTILINE)


def fence_blocks(text: str) -> list[tuple[int, int, int, int]]:
    """(block start, body start, body end, block end) for each fenced block, in order.

    A block closes at the first later line holding only the same fence character, at
    least as many times as it opened; an unclosed block runs to the end of the text.
    """
    blocks = []
    pos = 0
    while True:
        m = _OPEN.search(text, pos)
        if m is None:
            return blocks
        fence, info = m.group(1), m.group(2)
        if fence[0] == "`" and "`" in info:  # inline code on one line, not a fence
            pos = m.end()
            continue
        body = min(m.end() + 1, len(text))
        close = re.compile(rf"^[ \t]*{re.escape(fence[0])}{{{len(fence)},}}[ \t]*$", re.MULTILINE).search(text, body)
        if close is None:
            blocks.append((m.start(), body, len(text), len(text)))
            return blocks
        blocks.append((m.start(), body, close.start(), close.end()))
        pos = close.end()


def extract(path: Path, text: str) -> list[Span]:
    if is_code(path, text) or path.suffix.lower() in MARKDOWN_EXTS:
        return []  # code files are scanned as code in full (plain); markdown has its own surface
    return [Span(body, end, "code") for _, body, end, _ in fence_blocks(text)]
