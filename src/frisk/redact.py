"""Secret-like values in scan excerpts, masked as ****(len=N).

engine builds every excerpt through Redactor, so text, --json, --sarif/--sarif-out and
frisk-mcp output all carry the masked form. What counts as a secret is debug's pattern
(debug.secrets_pattern: a URL's userinfo, sk-/gh*_/github_pat_ tokens, a value after a
secret's name, a Bearer or Basic credential), here also after 'passwd' or 'auth' and after
'=>', plus PEM private-key blocks, AKIA/ASIA access-key ids, and high-entropy runs of 32
or more base64 or hex characters. Every pattern is a single pass over a character class
or a bounded repeat, so matching stays linear in the text.
"""
from __future__ import annotations

import math
import re
from bisect import bisect_right
from collections import Counter

from .debug import secrets_pattern

_NAMED = secrets_pattern(r"[^/?#\s]", r"[^\s\"'`,;]",
                         names=r"key|token|secret|passw(?:or)?d|auth(?!or)|cookie", assign=r"=>|=(?!=)|:")
_KEYS = re.compile(r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----[A-Za-z0-9+/=\s]*"
                   r"(?:-----END [A-Z0-9 ]{0,40}PRIVATE KEY-----)?"
                   r"|\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
_RUN = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{32,}={0,2}")
_MIN_ENTROPY = 3.0  # bits per character: random hex is ~4, random base64 ~6, a long word far less


def mask(value: str) -> str:
    return f"****(len={len(value)})"


def secret_spans(text: str) -> list[tuple[int, int]]:
    """The (start, end) of each secret in `text`, sorted, overlapping ones merged."""
    spans = [(m.end(1) if m.group(1) else m.start(), m.end()) for m in _NAMED.finditer(text)]
    spans += [m.span() for m in _KEYS.finditer(text)]
    spans += [m.span() for m in _RUN.finditer(text) if _random(m.group().rstrip("="))]
    merged: list[tuple[int, int]] = []
    for start, end in sorted(s for s in spans if s[1] > s[0]):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    return merged


def _random(run: str) -> bool:
    """A run that looks generated: letters and digits, with high per-character entropy."""
    if not (any(c.isdigit() for c in run) and any(c.isalpha() for c in run)):
        return False
    counts = Counter(run).values()
    return -sum(n / len(run) * math.log2(n / len(run)) for n in counts) >= _MIN_ENTROPY


def redact(text: str) -> str:
    """`text` with each secret masked."""
    return Redactor(text).window(0, len(text))


class Redactor:
    """Masks the secrets of one text in windows of it. The text is searched once, on the
    first window asked for, so a text with no finding costs nothing."""

    def __init__(self, text: str) -> None:
        self.text = text
        self._spans: list[tuple[int, int]] | None = None

    def window(self, start: int, end: int) -> str:
        """text[start:end] with each secret that overlaps it masked by its full length."""
        if self._spans is None:
            self._spans = secret_spans(self.text)
        spans = self._spans
        out: list[str] = []
        at = start
        i = max(0, bisect_right(spans, (start, len(self.text) + 1)) - 1)
        while i < len(spans) and spans[i][0] < end:
            s, e = spans[i]
            if e > at:
                out.append(self.text[at:max(s, at)])
                out.append(mask(self.text[s:e]))
                at = min(e, end)
            i += 1
        out.append(self.text[at:end])
        return "".join(out)
