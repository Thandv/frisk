"""A temp HOME for a test, so nothing reads the real home directory or the real package caches."""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

CACHE_VARS = ("FRISK_NPX_CACHE", "FRISK_UV_TOOLS", "FRISK_UV_CACHE", "FRISK_PIPX_VENVS")


def fake_home(case: unittest.TestCase, home: Path | None = None) -> Path:
    """Point HOME at `home` (default: a new empty temp dir) and unset the cache-root
    overrides for the rest of the test; both are restored afterwards."""
    if home is None:
        tmp = tempfile.TemporaryDirectory()
        case.addCleanup(tmp.cleanup)
        home = Path(tmp.name)
    patcher = mock.patch.dict(os.environ, {"HOME": str(home)})
    patcher.start()
    case.addCleanup(patcher.stop)
    for var in CACHE_VARS:
        os.environ.pop(var, None)  # patch.dict puts the original environment back
    return home
