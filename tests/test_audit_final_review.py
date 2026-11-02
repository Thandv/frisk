"""Final-review regressions for the MCP config audit (FR-E4 final review on-top).

Each test drives a hole the final review found through the CLI or the parser: the attack
input is now handled, and a matching legitimate input still works. Every path lives in a
temp dir with HOME patched to a directory inside it, so no real config or cache is read.
Payloads and canaries are assembled at runtime, hosts use the .invalid TLD, nothing is
executed and nothing touches the network.
Run: PYTHONPATH=src python3 -B -m unittest discover -s tests
"""
from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from _home import fake_home
from frisk import pin
from frisk.cli import main
from frisk.sources import parse_mcp_config


def run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with mock.patch("frisk.report._USE_COLOR", False), contextlib.redirect_stdout(out), \
            contextlib.redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class FinalReviewCase(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.home = self.tmp / "home"
        self.home.mkdir()
        fake_home(self, self.home)

    def file(self, rel: str, text: str) -> Path:
        path = self.home / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def write(self, path: Path, data: dict) -> str:
        path.write_text(json.dumps(data), encoding="utf-8")
        return str(path)


class SharedNameTest(FinalReviewCase):
    """frisk lock pins a server by its name and frisk verify finds it by that name. A
    top-level server named like a project server ('db (~/work/app)') used to share that
    name, so a decoy copy of a pinned server answered for it while the real one changed:
    verify said 'no drift'."""

    def setUp(self) -> None:
        super().setUp()
        self.app = self.home / "work" / "app"
        self.file("work/app/server.js", "console.log('approved')\n")
        self.file("work/other/server.js", "console.log('not what was approved')\n")
        self.approved = {"command": "node", "args": [str(self.app / "server.js")]}
        self.cfg = self.home / ".claude.json"
        self.lockfile = str(self.tmp / "lock.json")

    def lock(self, data: dict) -> None:
        self.write(self.cfg, data)
        for argv in (["lock", str(self.cfg)], ["lock", "--mcp-config", str(self.cfg)]):
            self.assertEqual(run([*argv, "--lockfile", self.lockfile])[0], 0)

    def test_a_decoy_named_like_a_project_server_does_not_hide_its_change(self) -> None:
        self.lock({"projects": {str(self.app): {"mcpServers": {"db": self.approved}}}})
        changed = {"command": "node", "args": [str(self.home / "work" / "other" / "server.js")]}
        self.write(self.cfg, {"mcpServers": {"db (~/work/app)": self.approved},
                              "projects": {str(self.app): {"mcpServers": {"db": changed}}}})
        code, out, _ = run(["verify", "--lockfile", self.lockfile])
        self.assertEqual(code, 1)
        self.assertIn("verify: DRIFT DETECTED", out)
        self.assertIn("+ added:   db (~/work/app) (2)", out)

    def test_every_server_has_its_own_name_and_a_fresh_lock_verifies(self) -> None:
        tilde = {"command": "node", "args": [str(self.home / "work" / "other" / "server.js")]}
        data = {"mcpServers": {"db (~/work/app)": self.approved, "db (~/work/app) (2)": self.approved},
                "projects": {str(self.app): {"mcpServers": {"db": self.approved}},
                             "~/work/app": {"mcpServers": {"db": tilde}}}}
        self.assertEqual([s.name for s in parse_mcp_config(self.write(self.cfg, data))],
                         ["db (~/work/app)", "db (~/work/app) (2)", "db (~/work/app) (3)", "db (~/work/app) (4)"])
        self.lock(data)  # pinned under four names, so verify right after lock is clean
        self.assertEqual(len(pin.read_lock(self.lockfile)["entries"]), 5)
        self.assertEqual(run(["verify", "--lockfile", self.lockfile])[0], 0)

    def test_names_that_do_not_collide_are_unchanged(self) -> None:
        data = {"mcpServers": {"db": self.approved, "db (2)": self.approved},
                "projects": {str(self.app): {"mcpServers": {"db": self.approved}}}}
        self.assertEqual([s.name for s in parse_mcp_config(self.write(self.cfg, data))],
                         ["db", "db (2)", "db (~/work/app)"])


if __name__ == "__main__":
    unittest.main()
