"""FRISK_DEBUG=1 prints debug lines to stderr; off prints nothing extra;
secrets are redacted. git is mocked; no network."""
from __future__ import annotations

import contextlib
import io
import logging
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from frisk import debug, mcp_server, sources

URL = "https://user:ghp_secrettoken123@github.com/o/r.git"
SENTINEL = "PROMPT-SENTINEL-7f3a"


def _ok(*a, **k):
    return SimpleNamespace(returncode=0, stdout="", stderr="")


def _clone(run):
    with mock.patch.object(sources.subprocess, "run", run), sources.materialize(URL):
        pass


class DebugLogTests(unittest.TestCase):
    def _stderr(self, switch, fn):
        """Run fn with the switch set (None = unset, even if the shell exports
        it) and return what reached stderr."""
        err = io.StringIO()
        with mock.patch.dict(os.environ), contextlib.redirect_stderr(err):
            os.environ.pop("FRISK_DEBUG", None)
            if switch is not None:
                os.environ["FRISK_DEBUG"] = switch
            debug.setup_debug()
            try:
                fn()
            finally:
                os.environ["FRISK_DEBUG"] = "0"
                debug.setup_debug()
        return err.getvalue()

    def test_off_prints_nothing(self):
        self.assertEqual(self._stderr(None, lambda: _clone(_ok)), "")
        self.assertEqual(self._stderr("0", lambda: _clone(_ok)), "")

    def test_on_logs_clone_without_url(self):
        err = self._stderr("1", lambda: _clone(_ok))
        self.assertIn("[frisk debug] frisk.sources git clone start args=6", err)
        self.assertIn("git clone end status=exit rc=0", err)
        self.assertNotIn("ghp_secrettoken123", err)
        self.assertNotIn("github.com", err)

    def test_failed_clone_logs_end_line(self):
        def timeout(*a, **k):
            raise subprocess.TimeoutExpired("git", 120)

        def run():
            # FR-E4 final review: a timed-out clone raises RuntimeError without the git command,
            # whose URL can carry a token (it was the TimeoutExpired itself); the end line is unchanged.
            with self.assertRaisesRegex(RuntimeError, r"^git clone timed out after 120 s$"):
                _clone(timeout)
        self.assertIn("git clone end status=error error=TimeoutExpired", self._stderr("1", run))

    def test_tool_call_logs_status_not_content(self):
        req = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
               "params": {"name": "scan_text", "arguments": {"text": SENTINEL}}}
        rest = mcp_server.TOOLS["scan_text"][1:]

        def fail(text):
            raise ValueError(text)

        def calls():
            # A tool's output and its error message can quote what it scanned.
            for fn in (lambda text: "echo: " + text, fail):
                with mock.patch.dict(mcp_server.TOOLS, {"scan_text": (fn, *rest)}):
                    self.assertIn(SENTINEL, mcp_server.handle(req)["result"]["content"][0]["text"])
        err = self._stderr("1", calls)
        self.assertIn("tool end name=scan_text status=ok", err)
        self.assertIn("tool end name=scan_text status=error error=ValueError", err)
        self.assertNotIn(SENTINEL, err)

    def test_swallowed_error_is_logged(self):
        with tempfile.TemporaryDirectory() as d:
            bad = Path(d) / "x.json"
            bad.write_text("{not json", encoding="utf-8")
            err = self._stderr("1", lambda: self.assertFalse(sources.looks_like_mcp_config(bad)))
        self.assertIn("not an MCP config (unreadable JSON) error=JSONDecodeError", err)

    def test_secrets_are_redacted(self):
        shapes = ("key=v1secret", '{"api_key": "v2secret"}',
                  "Authorization: Bearer v3secret", "sk-v4secret")
        err = self._stderr("1", lambda: [logging.getLogger("frisk.test").debug("x %s", s)
                                         for s in shapes])
        self.assertEqual(err.count("[REDACTED]"), 4)
        for s in ("v1secret", "v2secret", "v3secret", "v4secret"):
            self.assertNotIn(s, err)


if __name__ == "__main__":
    unittest.main()
