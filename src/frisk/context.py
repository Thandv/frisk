"""Where a span of a scanned text sits: code, a string, a comment, a markdown fence, prose...

classify(path, text, span) names the context (one of CONTEXTS) of text[start:end]. It is a
pure function of its arguments and the scan does not use it yet: a severity-by-context
policy would. It only lexes: nothing here compiles, evaluates or runs scanned content.

- Python: the stdlib tokenizer. A string is code_string, or code_docstring when it stands
  alone as a statement; a comment is code_comment. An f-string's (or t-string's)
  replacement fields, format specs included, are code on every Python version: 3.9-3.11
  give a whole f-string as one token, so the fields are found here, the same way for all.
- JavaScript/TypeScript and shell: a small hand lexer. A template literal's ${...}, and a
  shell $(...), ${...} or `...`, are code wherever they sit, strings included.
- Markdown: front matter, fenced code (md_fence), HTML comments, indented code, inline
  code, double-quoted mentions, prose. Fences are paired under two readings: with a run of
  backticks after text on a line opening a fence (as fences.fence_blocks pairs them, since
  an agent reads raw text) and without (as a renderer pairs them). What either reading puts
  in a fence is md_fence, so a decoy opener cannot turn a fenced payload into prose.
- JSON: json_command for each string surfaces/json_values scans as a command, json_string
  for the other strings.
- The proxy's texts, named by the paths TOOL_DESCRIPTION and TOOL_RESULT: the whole text.

When unsure (a tokenizer error, an unterminated string, comment or here-document, an
unknown file type, a span across two contexts, or a text too long to lex in bounded time:
over MAX_PYTHON_CHARS for Python, MAX_LEX_CHARS for the others) the answer is FALLBACK: code.
"""
from __future__ import annotations

import functools
import io
import re
import tokenize
from bisect import bisect_right
from pathlib import Path
from typing import Callable

from .rules import MARKDOWN_EXTS
from .surfaces import json_values
from .surfaces.fences import fence_blocks
from .surfaces.markdown import _COMMENT, _gaps, _indented_blocks, _inline_code

CONTEXTS = ("code", "code_string", "code_docstring", "code_comment", "md_fence", "md_inline_code", "md_indented",
            "md_html_comment", "md_quoted_mention", "md_prose", "json_command", "json_string", "front_matter",
            "tool_description", "tool_result")
FALLBACK = "code"
TOOL_DESCRIPTION, TOOL_RESULT = "<tool_description>", "<tool_result>"
# Lexing time bounds: a longer text is FALLBACK throughout. The hand lexers are linear, at
# up to about 1.2 s per MiB of the worst input on Python 3.9; the stdlib tokenizer is not
# linear on every input (3.14 takes quadratic time on one line of many f-strings).
MAX_LEX_CHARS = 512 * 1024
MAX_PYTHON_CHARS = 128 * 1024

_KIND_BY_EXT = {**{e: "python" for e in (".py", ".pyw", ".pyi")},
                **{e: "js" for e in (".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx")},
                **{e: "shell" for e in (".sh", ".bash", ".zsh", ".ksh")},
                **{e: "markdown" for e in MARKDOWN_EXTS}, ".json": "json"}
_SHEBANG = re.compile(r"#![^\n]*?\b(python[0-9.]*|node|deno|bun|sh|bash|zsh|ksh|dash)\b")


# (start, end, context): plain tuples, since a text can have a million of them.
Region = tuple[int, int, str]


def classify(path: str | Path, text: str, span: tuple[int, int]) -> str:
    """The context of text[span[0]:span[1]] in the file at `path`, or in the proxy text named
    by TOOL_DESCRIPTION or TOOL_RESULT. A span across two contexts is FALLBACK."""
    start, end = span
    if not 0 <= start <= end <= len(text):
        raise ValueError(f"span {span} is not inside a text of {len(text)} characters")
    starts, regions = _regions(_kind(str(path), text), text)
    _, region_end, context = regions[max(0, bisect_right(starts, start) - 1)]
    return context if end <= region_end else FALLBACK


def _kind(path: str, text: str) -> str:
    if path in (TOOL_DESCRIPTION, TOOL_RESULT):
        return path.strip("<>")
    kind = _KIND_BY_EXT.get(Path(path).suffix.lower())
    if kind == "json" and Path(path).name == "package.json":
        return "package_json"
    if kind is not None:
        return kind
    m = _SHEBANG.match(text)
    if m is None:
        return "unknown"
    return "python" if m.group(1).startswith("python") else "js" if m.group(1) in ("node", "deno", "bun") else "shell"


@functools.lru_cache(maxsize=8)
def _regions(kind: str, text: str) -> tuple[list[int], list[Region]]:
    """Regions that cover the text in order, with no gap and no overlap (neighbours of one
    context merged), and their start offsets."""
    if kind in ("tool_description", "tool_result"):
        return [0], [(0, len(text), kind)]
    finder = _FINDERS.get(kind)
    if finder is None or len(text) > (MAX_PYTHON_CHARS if kind == "python" else MAX_LEX_CHARS):
        return [0], [(0, len(text), FALLBACK)]
    # Between what a finder found: prose in markdown, code in a lexed language, and in JSON
    # (numbers, punctuation) FALLBACK.
    fill = {"markdown": "md_prose", "json": FALLBACK, "package_json": FALLBACK}.get(kind, "code")
    found = finder(text)
    found.sort()  # every finder but markdown's already gives them in order
    found.append((len(text), len(text), fill))
    out: list[Region] = []
    pos = 0
    for start, end, context in found:
        for piece in ((pos, start, fill), (max(pos, start), end, context)):
            if piece[1] <= piece[0]:
                continue
            if out and out[-1][2] == piece[2]:
                out[-1] = (out[-1][0], piece[1], piece[2])
            else:
                out.append(piece)
        pos = max(pos, end)
    out = out or [(0, 0, fill)]
    return [r[0] for r in out], out


# --- Python ------------------------------------------------------------------------------

_FSTRING_START = {"FSTRING_START", "TSTRING_START"}  # 3.12+ (t-strings: 3.14)
_FSTRING_END = {"FSTRING_END", "TSTRING_END"}
_TEMPLATE_PREFIXES = {"t", "tr", "rt"}  # before 3.14 a t-string lexes as NAME then STRING
_BEFORE_DOCSTRING = {None, "NEWLINE", "INDENT", "DEDENT", "ENCODING"}
_PREFIX = re.compile(r"[A-Za-z]*")
_FIELD_STOP = re.compile(r"[{}\[\]()'\"]")


def _python(text: str) -> list[Region]:
    """Strings, docstrings, comments and f-string parts; all FALLBACK on any tokenizer trouble."""
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except (tokenize.TokenError, SyntaxError, ValueError):
        return [(0, len(text), FALLBACK)]
    names = [tokenize.tok_name[t.type] for t in tokens]
    if "ERRORTOKEN" in names:  # 3.9-3.11 yield one where 3.12+ raise: the same answer on both
        return [(0, len(text), FALLBACK)]
    starts = [0] + [m.end() for m in re.finditer("\n", text)]

    def at(pos: tuple[int, int]) -> int:
        return starts[pos[0] - 1] + pos[1]

    out: list[Region] = []
    depth = opened = 0
    for i, (tok, name) in enumerate(zip(tokens, names)):
        if name in _FSTRING_START:
            opened = at(tok.start) if depth == 0 else opened
            depth += 1
        elif name in _FSTRING_END:
            depth -= 1
            if depth == 0:
                out += _fstring(text, opened, at(tok.end))
        elif depth:
            continue
        elif name == "COMMENT":
            out.append((at(tok.start), at(tok.end), "code_comment"))
        elif name == "STRING":
            prev = tokens[i - 1] if i else tok
            template = (i > 0 and names[i - 1] == "NAME" and prev.end == tok.start
                        and prev.string.lower() in _TEMPLATE_PREFIXES)
            prefix = _PREFIX.match(tok.string)
            if template or {"f", "t"} & set(prefix.group().lower() if prefix else ""):
                out += _fstring(text, at(prev.start if template else tok.start), at(tok.end))
            elif _neighbour(names, i, -1) in _BEFORE_DOCSTRING and _neighbour(names, i, 1) in ("NEWLINE", "ENDMARKER"):
                out.append((at(tok.start), at(tok.end), "code_docstring"))
            else:
                out.append((at(tok.start), at(tok.end), "code_string"))
    return out


def _neighbour(names: list[str], i: int, step: int) -> str | None:
    """The nearest token type before (step -1) or after (step 1) that is not a blank line or
    a comment; None past either end."""
    j = i + step
    while 0 <= j < len(names) and names[j] in ("NL", "COMMENT"):
        j += step
    return names[j] if 0 <= j < len(names) else None


def _fstring(text: str, start: int, end: int) -> list[Region]:
    """The f-string literal text[start:end]: its replacement fields are code, the rest
    code_string. A field left open runs to the closing quote."""
    prefix = _PREFIX.match(text, start)
    quote = prefix.end() if prefix else start
    width = 3 if end - quote >= 6 and text.startswith(text[quote] * 3, quote) else 1
    body_end = end - width
    out: list[Region] = []
    piece, pos = start, quote + width
    while True:
        j = text.find("{", pos, body_end)
        if j < 0:
            out.append((piece, end, "code_string"))
            return out
        if text.startswith("{{", j):
            pos = j + 2
            continue
        pos = _field_end(text, j + 1, body_end)
        out += [(piece, j, "code_string"), (j, pos, "code")]
        piece = pos


def _field_end(text: str, pos: int, end: int) -> int:
    """The offset after the '}' that closes a replacement field opened just before `pos`."""
    depth = 1
    while True:
        m = _FIELD_STOP.search(text, pos, end)
        if m is None:
            return end
        ch, pos = m.group(), m.end()
        if ch in "'\"":
            close = text.find(ch, pos, end)
            if close < 0:
                return end
            pos = close + 1
        elif ch in "{[(":
            depth += 1
        else:
            depth -= 1
            if depth == 0:
                return pos


# --- JavaScript / TypeScript and shell: bounded hand lexers ------------------------------
#
# Each keeps a stack of frames (kind, value, closer, origin): ("code", depth, closer, 0) for
# code at the top level or inside ${...}, $(...) or `...` (closer: the character that ends
# it, at nesting depth 0), and ("quoted", piece, closer, origin) for a template literal or a
# shell double-quoted string opened at origin, whose pieces (the current one from piece) are
# code_string. Each step jumps to the next character that matters with one regex search, so
# lexing is linear in the text. Whatever is left unterminated is FALLBACK from where it
# opened (from the outermost string still open) to the end.

_JS_CODE = re.compile(r"//|/\*|[\"'`{}/]")
_JS_QUOTED = re.compile(r"\\[\s\S]|`|\$\{")
_JS_REGEX_AFTER = set("(,=:[!&|?{};+-*%<>~^")
_JS_REGEX_STOP = re.compile(r"\\.|[\[\]/\n]")
_SH_CODE = re.compile(r"<<-?[ \t]*['\"]?[A-Za-z_]\w*['\"]?|\$\(|\$\{|\$'|\\[\s\S]|[#'\"`(){}\n]")
_SH_QUOTED = re.compile(r"\\[\s\S]|\"|\$\(|\$\{|`")
_SH_WORD_START = set(" \t\n;&|()")
# The end of a one-line string with escapes (JS), a multi-line one with escapes (shell $'..')
# and one with none (shell '..').
_STRING_END: dict[tuple[str, bool, bool], re.Pattern[str]] = {
    (q, True, True): re.compile(r"\\[\s\S]|\n|" + q) for q in ("'", '"')}
_STRING_END.update({("'", True, False): re.compile(r"\\[\s\S]|'"), ("'", False, False): re.compile("'")})
_OPENS = {"}": "{", ")": "(", "`": ""}
_CLOSES = {"${": "}", "$(": ")", "`": "`"}
_Stack = list[tuple[str, int, str, int]]
# What a language's lexer does at a token in code: (text, offset, token, stack, regions) ->
# the offset to go on from, or -1 when it is unterminated, so the rest is FALLBACK.
_Token = Callable[[str, int, str, _Stack, list[Region]], int]


def _js(text: str) -> list[Region]:
    no_regex_before = [0]  # a regex literal that did not close: none starts again before here
    return _lex(text, _JS_CODE, _JS_QUOTED,
                lambda t, at, tok, stack, out: _js_token(t, at, tok, stack, out, no_regex_before))


def _shell(text: str) -> list[Region]:
    heredocs: list[tuple[str, bool]] = []
    return _lex(text, _SH_CODE, _SH_QUOTED,
                lambda t, at, tok, stack, out: _sh_token(t, at, tok, stack, out, heredocs))


def _lex(text: str, code_rx: re.Pattern[str], quoted_rx: re.Pattern[str], token: _Token) -> list[Region]:
    out: list[Region] = []
    stack: _Stack = [("code", 0, "", 0)]
    pos = 0
    while pos < len(text):
        kind, value, closer, origin = stack[-1]
        m = (quoted_rx if kind == "quoted" else code_rx).search(text, pos)
        if m is None:
            break
        tok, pos = m.group(), m.end()
        if kind == "quoted":
            if tok == closer:
                out.append((value, pos, "code_string"))
                stack.pop()
            elif tok[0] != "\\":  # code inside the string: ${, $( or a backtick
                out.append((value, m.start(), "code_string"))
                stack.append(("code", 0, _CLOSES[tok], 0))
        elif closer and tok == closer and value == 0:
            stack.pop()
            if stack[-1][0] == "quoted":  # the string's next piece starts here
                stack[-1] = ("quoted", pos, stack[-1][2], stack[-1][3])
        elif tok in ("${", "$("):
            stack.append(("code", 0, _CLOSES[tok], 0))
        elif closer and tok == _OPENS[closer]:
            stack[-1] = (kind, value + 1, closer, origin)
        elif closer and tok == closer:
            stack[-1] = (kind, value - 1, closer, origin)
        elif tok not in ("{", "}", "(", ")"):
            pos = token(text, m.start(), tok, stack, out)
            if pos < 0:
                return _unsure(out, stack, m.start(), len(text))
    return _unsure(out, stack, len(text), len(text))


def _unsure(out: list[Region], stack: _Stack, at: int, end: int) -> list[Region]:
    """The regions, with FALLBACK from `at` (or from the outermost string still open, which
    then never closed) to `end`."""
    cut = min([at] + [origin for kind, _v, _c, origin in stack if kind == "quoted"])
    while out and out[-1][0] >= cut:
        out.pop()
    if out and out[-1][1] > cut:
        out[-1] = (out[-1][0], cut, out[-1][2])
    if cut < end:
        out.append((cut, end, FALLBACK))
    return out


def _js_token(text: str, at: int, tok: str, stack: _Stack, out: list[Region], no_regex_before: list[int]) -> int:
    """A comment, string, template or regex literal at `at`: the offset after it (-1 when it
    is unterminated, so the rest is code)."""
    if tok == "//":
        end = text.find("\n", at)
        end = len(text) if end < 0 else end
        out.append((at, end, "code_comment"))
        return end
    if tok == "/*":
        end = text.find("*/", at + 2)
        if end < 0:
            return -1
        out.append((at, end + 2, "code_comment"))
        return end + 2
    if tok == "`":
        stack.append(("quoted", at, "`", at))
        return at + 1
    if tok == "/":
        return _js_slash(text, at, no_regex_before)
    return _string(text, at, at + 1, tok, out, escapes=True, one_line=True)


def _js_slash(text: str, at: int, no_regex_before: list[int]) -> int:
    """After a '/' that is not a comment: a regex literal is skipped (it is code, but a quote in
    it must not open a string); a division is one character. A regex literal follows an
    operator or an opening bracket, or starts the text, and closes on its line. When one
    does not, no other is tried before that line ends, so no line is read twice."""
    before = text[max(0, at - 64):at].rstrip()
    if at < no_regex_before[0] or (before[-1:] not in _JS_REGEX_AFTER and (before or at > 64)):
        return at + 1
    pos, in_class = at + 1, False
    while True:
        m = _JS_REGEX_STOP.search(text, pos)
        if m is None or m.group() == "\n":
            no_regex_before[0] = len(text) if m is None else m.start()
            return at + 1  # no closing '/' on the line: a division after all
        pos = m.end()
        if m.group() == "[":
            in_class = True
        elif m.group() == "]":
            in_class = False
        elif m.group() == "/" and not in_class:
            return pos


def _string(text: str, at: int, pos: int, quote: str, out: list[Region], escapes: bool, one_line: bool) -> int:
    """The string opened at `at` (its body from `pos`): code_string up to its closing quote.
    A one-line string that meets a newline first is FALLBACK up to there, and lexing goes on."""
    rx = _STRING_END[(quote, escapes, one_line)]
    while True:
        m = rx.search(text, pos)
        if m is None:
            return -1
        pos = m.end()
        if m.group() == quote:
            out.append((at, pos, "code_string"))
            return pos
        if m.group() == "\n":
            out.append((at, m.start(), FALLBACK))
            return pos


def _sh_token(text: str, at: int, tok: str, stack: _Stack, out: list[Region],
              heredocs: list[tuple[str, bool]]) -> int:
    """A comment, string, backquote or here-document at `at` (shell): the offset after it, or
    -1 when it is unterminated, so the rest is code."""
    if tok == "\n":
        return _heredoc_bodies(text, at + 1, heredocs, out)
    if tok.startswith("<<"):
        heredocs.append((tok[2:].lstrip("-").strip(" \t'\""), tok.startswith("<<-")))
    elif tok == "#" and (at == 0 or text[at - 1] in _SH_WORD_START):
        end = text.find("\n", at)
        end = len(text) if end < 0 else end
        out.append((at, end, "code_comment"))
        return end
    elif tok == "'":
        return _string(text, at, at + 1, "'", out, escapes=False, one_line=False)
    elif tok == "$'":
        return _string(text, at, at + 2, "'", out, escapes=True, one_line=False)
    elif tok == '"':
        stack.append(("quoted", at, '"', at))
    elif tok == "`":
        stack.append(("code", 0, "`", 0))
    return at + len(tok)


def _heredoc_bodies(text: str, pos: int, heredocs: list[tuple[str, bool]], out: list[Region]) -> int:
    """Skip the bodies of the here-documents opened on the line that just ended: FALLBACK,
    since what reads them is unknown. An unterminated one runs to the end of the text."""
    while heredocs:
        word, tabs = heredocs.pop(0)
        m = re.compile(r"^" + ("\t*" if tabs else "") + re.escape(word) + r"$", re.MULTILINE).search(text, pos)
        if m is None:
            return -1
        out.append((pos, m.start(), FALLBACK))
        pos = m.end()
    return pos


# --- markdown ----------------------------------------------------------------------------

_FRONT_MATTER = re.compile(r"---[ \t]*\n(?:[^\n]*\n)*?(?:---|\.\.\.)[ \t]*(?:\n|\Z)")
# A fence run; group 1 takes part when only indentation comes before it on its line.
_FENCE_RUN = re.compile(r"(^[ \t]*)?(`{3,}|~{3,})", re.MULTILINE)
# A double-quoted mention on one line; its body never holds another opening quote, so each
# opening quote is read past once.
_QUOTED = re.compile("\"[^\"\n]{1,200}\"|\u201c[^\u201c\u201d\n]{1,200}\u201d")


def _markdown(text: str) -> list[Region]:
    """Each form in its order of precedence, each found only where no earlier one is."""
    out: list[Region] = []
    taken: list[tuple[int, int]] = []

    def add(found: list[tuple[int, int]], context: str) -> None:
        nonlocal taken
        out.extend((s, e, context) for s, e in found)
        taken = sorted(taken + found)  # found lies in the gaps of taken: two sorted runs, merged

    def free() -> list[tuple[int, int]]:
        return _gaps(taken, len(text))

    front = _FRONT_MATTER.match(text)
    after = front.end() if front else 0
    add([front.span()] if front else [], "front_matter")
    add([(max(s, after), e) for s, e in _fences(text) if e > after], "md_fence")
    add([m.span() for a, b in free() for m in _COMMENT.finditer(text, a, b)], "md_html_comment")
    add([blk for a, b in free() for blk in _indented_blocks(text, a, b)], "md_indented")
    add([code for a, b in free() for code in _inline_code(text, a, b)], "md_inline_code")
    add([m.span() for a, b in free() for m in _QUOTED.finditer(text, a, b)], "md_quoted_mention")
    return out


def _fences(text: str) -> list[tuple[int, int]]:
    """Fenced blocks, start to end, under both readings: as fences.fence_blocks pairs them, and
    with every run that has text before it on its line blanked out (a renderer's pairing)."""
    blanked = _FENCE_RUN.sub(lambda m: m.group() if m.group(1) is not None else " " * len(m.group()), text)
    readings = fence_blocks(text) + (fence_blocks(blanked) if blanked != text else [])
    return _union([(s, e) for s, _b, _c, e in readings])


def _union(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for s, e in sorted(spans):
        if merged and s <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(e, merged[-1][1]))
        else:
            merged.append((s, e))
    return merged


# --- JSON --------------------------------------------------------------------------------

def _json(text: str, name: str = "x.json") -> list[Region]:
    """Each string literal: json_command when json_values scans it as (part of) a command,
    else json_string. Not JSON: none, so all of it is code."""
    try:
        found = json_values.literals(Path(name), text)
    except (ValueError, RecursionError):
        return []
    return [(s, e, "json_command" if command else "json_string") for s, e, command in found]


def _package_json(text: str) -> list[Region]:
    return _json(text, "package.json")


_FINDERS: dict[str, Callable[[str], list[Region]]] = {
    "python": _python, "js": _js, "shell": _shell, "markdown": _markdown, "json": _json, "package_json": _package_json}
