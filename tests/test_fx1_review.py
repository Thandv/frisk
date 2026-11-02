"""Review regressions for FR-FX1 (independent review on-top).

Each test drives a hole the review found through the CLI, the lock or the redactor: the
attack input is now handled, and a matching legitimate input still works. Every path lives
in a temp dir with HOME patched to a directory inside it, so no real config or cache is
read. Canaries are assembled at runtime, hosts use the .invalid TLD, nothing is executed
and nothing touches the network.
Run: PYTHONPATH=src python3 -B -m unittest discover -s tests
"""
from __future__ import annotations

import contextlib
import io
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from _home import fake_home
from frisk.cli import main
from frisk.debug import redact

CANARY = "c4n" + "ary-" + "f1x1" + "a7e5"


def run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with mock.patch("frisk.report._USE_COLOR", False), contextlib.redirect_stdout(out), \
            contextlib.redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class ReviewCase(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.home = self.tmp / "home"
        self.server = self.home / "srv" / "server.js"
        self.server.parent.mkdir(parents=True)
        self.server.write_text("console.log(1)\n", encoding="utf-8")
        fake_home(self, self.home)
        self.cfg = self.tmp / "mcp.json"
        self.lockfile = str(self.tmp / "lock.json")

    def entry(self, spec: dict) -> None:
        self.cfg.write_text(json.dumps({"mcpServers": {"srv": spec}}), encoding="utf-8")

    def node(self, **extra: object) -> dict:
        return {"command": "node", "args": [str(self.server)], **extra}


class RedactionTimeTest(ReviewCase):
    """sev 5: the redactor matched a key/token/secret/password/authorization/cookie name from
    each occurrence and scanned the rest of its word every time, so a long word holding many
    names and no '=' took quadratic time. Since FR-FX1 10 every value of every audited server
    passes through it (the launch digest is made when the config is parsed): one 64 KiB
    argument made 'frisk --mcp-config' take 49 s (main: 0.16 s), 1 MiB about three hours, in a
    scan, a lock and a verify alike. CPU time, so machine load does not matter; the linear
    check takes milliseconds, so 2 s is a wide margin."""

    WORDS = (("key", "key" * (1 << 15)), ("Token", "Token" * (1 << 14)), ("api_key_", "api_key_" * (1 << 13)))

    def test_a_long_run_of_names_is_redacted_in_linear_time(self) -> None:
        for label, word in self.WORDS:
            with self.subTest(label):
                t0 = time.process_time()
                self.assertEqual(redact(word), word)
                self.assertEqual(redact(word + "=" + CANARY), word + "=[REDACTED]")
                self.assertLess(time.process_time() - t0, 2.0)

    def test_a_config_holding_one_is_audited_in_linear_time(self) -> None:
        self.entry(self.node(args=[str(self.server), self.WORDS[0][1]]))
        t0 = time.process_time()
        code, out, _err = run(["--mcp-config", str(self.cfg)])
        self.assertLess(time.process_time() - t0, 2.0)
        self.assertEqual(code, 0)
        self.assertIn("[PASS ] srv", out)

    def test_a_name_is_still_found_anywhere_in_its_word(self) -> None:
        # The name is now matched from the start of its word: the same values are redacted.
        for text, shown in (("--api-key=" + CANARY, "--api-key=[REDACTED]"),
                            ("apikey=" + CANARY, "apikey=[REDACTED]"),
                            ("-Dapi.key=" + CANARY, "-Dapi.key=[REDACTED]"),
                            ('{"api_key": "' + CANARY + '"}', '{"api_key": "[REDACTED]'),
                            ("monkey=" + CANARY, "monkey=[REDACTED]"),
                            ("key-id=" + CANARY, "key-id=" + CANARY),
                            ("sk-abc_key=" + CANARY, "[REDACTED]=" + CANARY),
                            # a word that starts like a token is the token, also with a name in it
                            ("gh" + "p_abckey=" + CANARY, "[REDACTED]=" + CANARY)):
            with self.subTest(text.replace(CANARY, "<canary>")):
                self.assertEqual(redact(text), shown)


if __name__ == "__main__":
    unittest.main()
