"""JSON files (.json) by meaning: each string is scanned as the value it decodes to.

The file is parsed as data only (json.loads), so a malformed one raises here: the engine
reports it as a coverage.surface_error, and the raw text is still scanned (plain). Then
its string literals are walked in order with their keys:

- the value of a command, run, script, shell or exec key (an array of strings under one
  is joined with spaces), the strings of an args array (joined, after the sibling
  command, wherever the two sit in their object), and any other string value holding a
  shell pipeline, are scanned as code. In package.json the commands are the "scripts"
  values (as the package_json surface reads them, here decoded), and nothing else is;
- every string, key or value, written with a backslash escape is also scanned as the text
  it decodes to (text rules and the hidden-Unicode check): written plainly, a string is
  the raw text the whole-file text scan already reads.

A decoded string is not a stretch of the file, so its span carries the decoded text, and
its findings are reported at the line of its literal (a JSON string is on one line).
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import NamedTuple

from . import Span

# String literals and the punctuation that gives them their place; numbers, true, false
# and null are skipped. Used only on text json.loads accepted, where every string closes.
_TOKEN = re.compile(r'"(?:[^"\\]|\\.)*"|[{}\[\]:,]')
# A shell pipeline: a word, '|' (not '||') and a word.
_PIPE = re.compile(r"[^|\s][ \t]*\|[ \t]*[^|\s]")
CODE_KEYS = frozenset({"command", "run", "script", "shell", "exec"})
_JOINED_KEYS = CODE_KEYS | {"args"}


class _Literal(NamedTuple):
    start: int  # offset of the opening quote
    end: int  # offset after the closing quote
    value: str  # the decoded string
    escaped: bool  # written with a backslash escape


class _Frame:
    """An open object or array, and the key it is the value of in its object (an array's
    elements, and what nests in them, keep that key; None at the top)."""

    def __init__(self, is_object: bool, key: str | None) -> None:
        self.is_object = is_object
        self.key = key
        self.value_key: str | None = None  # an object's key whose value comes next
        self.expect_key = is_object
        self.strings: list[_Literal] = []  # an array's string elements under a joined key
        self.command: _Literal | None = None  # an object's command string
        self.args: list[_Literal] | None = None  # an object's args strings


def _owner(frame: _Frame | None) -> str | None:
    """The key a value at this point belongs to."""
    if frame is None:
        return None
    return frame.value_key if frame.is_object else frame.key


def extract(path: Path, text: str) -> list[Span]:
    if path.suffix.lower() != ".json":
        return []
    json.loads(text)
    package = path.name == "package.json"
    spans: list[Span] = []
    stack: list[_Frame] = []
    for m in _TOKEN.finditer(text):
        tok = m.group()
        top = stack[-1] if stack else None
        if tok in ("{", "["):
            stack.append(_Frame(tok == "{", _owner(top)))
        elif tok in ("}", "]"):
            _close(stack.pop(), stack[-1] if stack else None, spans)
        elif tok == ",":
            if top is not None and top.is_object:
                top.expect_key = True
        elif tok != ":":
            escaped = "\\" in tok
            lit = _Literal(m.start(), m.end(), json.loads(tok) if escaped else tok[1:-1], escaped)
            if lit.escaped:
                spans.append(Span(lit.start, lit.end, "text", lit.value))
            if top is not None and top.is_object and top.expect_key:
                top.value_key, top.expect_key = lit.value, False
            else:
                _value(lit, top, package, spans)
    return spans


def _value(lit: _Literal, top: _Frame | None, package: bool, spans: list[Span]) -> None:
    """A string value: code when its key says so or it holds a pipeline (in package.json,
    when it is a script). The strings of an array under a code key or args are kept for the
    join instead."""
    key = _owner(top)
    if top is not None and not top.is_object and key in _JOINED_KEYS:
        top.strings.append(lit)
        return
    if top is not None and top.is_object and key == "command":
        top.command = lit
    if package:
        command = top is not None and top.is_object and top.key == "scripts"
    else:
        command = key in CODE_KEYS or _PIPE.search(lit.value) is not None
    if command:
        spans.append(_code([lit]))


def _close(done: _Frame, parent: _Frame | None, spans: list[Span]) -> None:
    """A closed array under a code key is one command; an args array waits for its object,
    which joins it after its command."""
    if done.is_object:
        if done.args:
            spans.append(_code(([done.command] if done.command else []) + done.args))
    elif done.key == "args" and parent is not None and parent.is_object:
        parent.args = done.strings
    elif done.strings:
        spans.append(_code(done.strings))


def _code(parts: list[_Literal]) -> Span:
    """A code span: one literal written with no escape is its raw body; otherwise the decoded
    words joined with spaces, reported at the first literal's line."""
    first = parts[0]
    if len(parts) == 1 and not first.escaped:
        return Span(first.start + 1, first.end - 1, "code")
    return Span(first.start, parts[-1].end, "code", " ".join(p.value for p in parts))
