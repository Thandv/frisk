"""Markdown (.md, .markdown, .mdc): every form of code is scanned as code, and HTML comments,
which renderers hide, are marked as their own text span (kind md_html_comment).

Code forms: fenced blocks (``` or ~~~, any length, unclosed ones run to the end of the
file; see fences.fence_blocks), indented code blocks (4 spaces or a tab after a blank
line, outside a list) and inline code spans. Inline code in an ordinary document (not an
agent-instruction file, see instructions.py) is its own kind, md_inline_code: code rules
run on it but cap at warn, so a README that mentions `eval()` does not block. The whole
file is text-scanned by plain.
"""
from __future__ import annotations

import re
from pathlib import Path

from ..rules import MARKDOWN_EXTS, is_code
from . import Span
from .fences import fence_blocks
from .instructions import is_instruction_file

_COMMENT = re.compile(r"<!--.*?(?:-->|\Z)", re.DOTALL)  # an unclosed comment hides the rest
_LINE = re.compile(r"[^\n]*\n|[^\n]+")
_LIST_ITEM = re.compile(r"[ \t]{0,3}(?:[-*+]|\d{1,9}[.)])(?:[ \t]|$)")
_BLANK_LINE = re.compile(r"\n[ \t]*\n")
_TICKS = re.compile(r"`+")


def _gaps(regions: list[tuple[int, int]], end: int) -> list[tuple[int, int]]:
    """The stretches of [0, end) that no region covers (regions sorted, not overlapping)."""
    gaps, pos = [], 0
    for start, stop in regions:
        if start > pos:
            gaps.append((pos, start))
        pos = max(pos, stop)
    if pos < end:
        gaps.append((pos, end))
    return gaps


def _inline_code(text: str, start: int, end: int) -> list[tuple[int, int]]:
    """Inline code in text[start:end]: a backtick run up to the next run of the same length in
    the same paragraph. Each paragraph is paired in one pass, so the cost stays linear."""
    spans = []
    para = start
    for stop in [m.start() for m in _BLANK_LINE.finditer(text, start, end)] + [end]:
        runs = list(_TICKS.finditer(text, para, stop))
        closer: list[int | None] = [None] * len(runs)
        last: dict[int, int] = {}
        for k in range(len(runs) - 1, -1, -1):
            width = runs[k].end() - runs[k].start()
            closer[k], last[width] = last.get(width), k
        k = 0
        while k < len(runs):
            j = closer[k]
            if j is None:
                k += 1
                continue
            spans.append((runs[k].end(), runs[j].start()))
            k = j + 1
        para = stop
    return spans


def _indented_blocks(text: str, start: int, end: int) -> list[tuple[int, int]]:
    """Indented code blocks in text[start:end]: after a blank line, not inside a list."""
    blocks: list[tuple[int, int]] = []
    after_blank, in_list, block = True, False, None
    for m in _LINE.finditer(text, start, end):
        line = m.group().rstrip("\n")
        if not line.strip():
            after_blank = True
            continue
        indented = line.startswith(("    ", "\t"))
        if indented and (block is not None or (after_blank and not in_list)):
            block = (block[0] if block else m.start(), m.start() + len(line))
        else:
            if block:
                blocks.append(block)
                block = None
            if not indented:
                in_list = _LIST_ITEM.match(line) is not None or (in_list and not after_blank)
        after_blank = False
    if block:
        blocks.append(block)
    return blocks


def extract(path: Path, text: str) -> list[Span]:
    if path.suffix.lower() not in MARKDOWN_EXTS or is_code(path, text):
        return []
    fences = fence_blocks(text)
    blocks = [(start, end) for start, _, _, end in fences]
    comments = [m.span() for a, b in _gaps(blocks, len(text)) for m in _COMMENT.finditer(text, a, b)]
    hidden = sorted(blocks + comments)
    spans = [Span(body, end, "code") for _, body, end, _ in fences]
    spans += [Span(s, e, "md_html_comment") for s, e in comments]
    indented = [blk for a, b in _gaps(hidden, len(text)) for blk in _indented_blocks(text, a, b)]
    spans += [Span(s, e, "code") for s, e in indented]
    inline = "code" if is_instruction_file(path) else "md_inline_code"
    for a, b in _gaps(sorted(hidden + indented), len(text)):
        spans += [Span(s, e, inline) for s, e in _inline_code(text, a, b)]
    return spans
