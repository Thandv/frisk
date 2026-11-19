"""A guard for the proxy tests: a ResourceWarning (a file or pipe left unclosed) fails the test that caused it.

Python raises a ResourceWarning from a finalizer, where it only prints "Exception ignored" and
never fails anything, and ignores it by default. So the guard records warnings instead, forces
a garbage collection at the end of the test (so the leak surfaces in the test that made it,
not in a later one) and fails on what it recorded. The recording is scoped to a test that
inherits NoResourceWarnings, never global. The proxy under test often runs as a child process,
which no filter here reaches: such a test starts the child with CHILD_WARNINGS in its
environment and passes the child's stderr to check_child_stderr.
"""
from __future__ import annotations

import contextlib
import gc
import os
import unittest
import warnings
from typing import IO

CHILD_WARNINGS = {"PYTHONWARNINGS": "always::ResourceWarning"}  # the child prints them to its stderr


def check_child_stderr(test: unittest.TestCase, stream: IO | None) -> None:
    """Fail `test` if what a finished child left unread on its stderr holds a ResourceWarning.
    Reads only what is there (never blocks: a grandchild may hold the pipe open)."""
    if stream is None or stream.closed:
        return
    fd = stream.fileno()
    os.set_blocking(fd, False)
    seen = b""
    with contextlib.suppress(BlockingIOError, OSError):
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            seen += chunk
    test.assertNotIn(b"ResourceWarning", seen, seen.decode("utf-8", "replace"))


class NoResourceWarnings(unittest.TestCase):
    """Base class for a proxy test: a subclass that defines setUp calls super().setUp() first."""

    def setUp(self) -> None:
        super().setUp()
        recorder = warnings.catch_warnings(record=True)
        caught = recorder.__enter__()
        warnings.simplefilter("always", ResourceWarning)
        # Registered first, so it runs last: after every cleanup that closes what the test opened.
        self.addCleanup(self._no_leaks, recorder, caught)

    def _no_leaks(self, recorder: warnings.catch_warnings, caught: list) -> None:
        try:
            gc.collect()
        finally:
            recorder.__exit__(None, None, None)
        leaks = [str(w.message) for w in caught if issubclass(w.category, ResourceWarning)]
        self.assertEqual(leaks, [], "a resource was left open")
