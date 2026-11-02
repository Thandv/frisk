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
def _secrets(userinfo: str, value: str) -> re.Pattern[str]:
    """The secrets, where `userinfo` and `value` are the characters a URL's userinfo and a
    secret value may span."""
    return re.compile(
        rf"(?i)(?<=://){userinfo}*(?=@)"
        r"|\b(?:sk|gh[pousr]|github_pat)[-_][A-Za-z0-9_-]+"
        r"|((?<!\w)(?=\w*?(?:key|token|secret|password|authorization|cookie))\w+[\"']?\s*[=:]\s*[\"']?)"
        rf"(?:(?:bearer|basic)\s+(?!-))?{value}+"
        rf"|\b(?:bearer|basic)\s+(?!-){value}+")


# In a debug line a secret runs to the next whitespace (in a URL, up to the host part).
_SECRET = _secrets(r"[^/?#\s]", r"\S")
# In a value frisk lock hashes, a redacted span is not drift when it changes, so it must not
# hold what decides what runs: there a secret is a run of the characters of a token or
# password that no shell, path list, option list, JSON text or URL host part gives a meaning
# to. A ';', '|', '&', '$', '(', '/', ':', ',', a quote, a backslash (where URL parsers end a
# host) or whitespace ends it, and what follows (a command, the next path, option or host)
# stays pinned.
_PINNED = _secrets(r"[\w.+=%:@!*~-]", r"[\w.+=%@!*-]")


def redact(text: str, pinned: bool = False) -> str:
    """Text with each secret replaced by '[REDACTED]': a debug line, or (pinned) a value
    frisk lock hashes (sources._pin_digest), where a secret ends at the first character that
    could change what runs."""
    return (_PINNED if pinned else _SECRET).sub(lambda m: (m.group(1) or "") + "[REDACTED]", text)


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
