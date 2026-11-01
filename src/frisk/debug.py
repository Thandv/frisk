"""Opt-in debug logs: FRISK_DEBUG=1 sends the `frisk` logger's DEBUG lines
to stderr as `[frisk debug] ...`. Off (unset or 0) adds nothing."""
from __future__ import annotations

import logging
import os
import re
import sys
import time

log = logging.getLogger("frisk")

_SECRET = re.compile(
    r"(?i)((?:key|token|secret|password|authorization|cookie)\w*[\"']?\s*[=:]\s*[\"']?)(?:bearer\s+)?\S+"
    r"|\b(?:sk|gh[pousr]|github_pat)[-_][A-Za-z0-9_-]+|\bbearer\s+\S+")


def redact(text: str) -> str:
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
