"""Opt-in debug logs: FRISK_DEBUG=1 sends the `frisk` logger's DEBUG lines
to stderr as `[frisk debug] ...`. Off (unset or 0) adds nothing."""
from __future__ import annotations

import logging
import os
import re
import sys
import time

log = logging.getLogger("frisk")

# A URL's userinfo (up to the last '@' of the part after '://'; it comes first, so a user
# named 'token' leaves the host), a value after a key/token/secret/password/authorization/
# cookie name and '=' or ':', a Bearer or Basic credential (never an option after the word:
# 'basic -javaagent:x' stays), and sk-, gh*_ and github_pat_ tokens. A name is matched from
# the start of its word (the lookahead finds it anywhere in the word), so each word is read
# once: matched from each name in it, a long word of names with no '=' took quadratic time.
# A token is tried first, so a word that starts like one is redacted whole, as before.
_SECRET = re.compile(
    r"(?i)(?<=://)[^/?#\s]*(?=@)"
    r"|\b(?:sk|gh[pousr]|github_pat)[-_][A-Za-z0-9_-]+"
    r"|((?<!\w)(?=\w*?(?:key|token|secret|password|authorization|cookie))\w+[\"']?\s*[=:]\s*[\"']?)"
    r"(?:(?:bearer|basic)\s+)?\S+"
    r"|\b(?:bearer|basic)\s+(?!-)\S+")


def redact(text: str) -> str:
    """Text with each secret _SECRET finds replaced by '[REDACTED]': debug lines, and every
    value frisk lock hashes (sources._pin_digest)."""
    return _SECRET.sub(lambda m: (m.group(1) or "") + "[REDACTED]", text)


class _Stderr(logging.StreamHandler):
    """Writes to whatever sys.stderr is at emit time (never a stale capture)."""

    @property
    def stream(self):
        return sys.stderr

    @stream.setter
    def stream(self, _value):
        pass


class _Redacting(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return redact(super().format(record))


def setup_debug() -> None:
    """Attach one stderr DEBUG handler when FRISK_DEBUG=1, else remove it."""
    mine = [h for h in log.handlers if getattr(h, "_frisk_debug", False)]
    if os.environ.get("FRISK_DEBUG") != "1":
        for h in mine:
            log.removeHandler(h)
        if mine:
            log.setLevel(logging.NOTSET)
        return
    if mine:
        return
    h = _Stderr()
    h.setFormatter(_Redacting("[frisk debug] %(name)s %(message)s"))
    h._frisk_debug = True  # type: ignore[attr-defined]
    log.addHandler(h)
    log.setLevel(logging.DEBUG)


def ms_since(t0: float) -> int:
    return int((time.monotonic() - t0) * 1000)
