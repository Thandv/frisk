"""FR-E6 F3.07: the lockfile catches real upstream changes.

A server is pinned by its whole launch spec (FR-E4's launch digest: command, every arg, cwd,
the URL without query, env and header NAMES, never values), so an added flag or a changed
URL path is DRIFT and a rotated env value is not. frisk lock says when an npx/uvx/pipx
package is not pinned to an exact version. Local paths inside the lockfile's directory
are also stored relative to it, so a lock verifies from any working directory and in a
copy of the tree. The lockfile version stays 1; any other version (or none) exits 2.
Temp dirs and a temp HOME only. Run: PYTHONPATH=src python3 -B -m unittest discover -s tests
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from _home import fake_home
from frisk import pin
from frisk.cli import main

UNPINNED = "unpinned: upstream changes cannot be detected; pin {}@x.y.z"


def run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class SpecCase(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(os.path.realpath(tmp.name))
        fake_home(self, self.tmp / "home")
        (self.tmp / "home").mkdir()
        self.a = self.tmp / "a"
        self.a.mkdir()
        self.cfg = self.a / ".mcp.json"
        self.lockfile = self.a / ".frisk-lock.json"
        self.addCleanup(os.chdir, os.getcwd())

    def config(self, servers: dict) -> None:
        self.cfg.write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")

    def lock(self) -> tuple[int, str]:
        code, _out, err = run(["lock", "--mcp-config", str(self.cfg), "--lockfile", str(self.lockfile)])
        return code, err

    def status(self, name: str) -> str:
        report = pin.verify_lock(pin.read_lock(str(self.lockfile)), self.lockfile.parent)
        (row,) = [r for r in report if r["entry"] == f"{self.cfg}::{name}"]
        return row["status"]


class TestSpecDigest(SpecCase):
    SERVER = {"command": "node", "args": ["/opt/acme/server.js", "--port", "7"], "cwd": "/opt/acme",
              "env": {"API_TOKEN": "one"}, "url": "https://api.example.invalid/v1/mcp?session=1"}

    def drift_after(self, change: dict) -> str:
        self.config({"s": self.SERVER})
        self.assertEqual(self.lock()[0], 0)
        self.config({"s": {**self.SERVER, **change}})
        return self.status("s")

    def test_what_changes_how_a_server_starts_is_drift(self) -> None:
        for label, change in (("an added flag", {"args": [*self.SERVER["args"], "--allow-all"]}),
                              ("the url path", {"url": "https://api.example.invalid/v2/mcp?session=1"}),
                              ("the cwd", {"cwd": "/opt/other"}),
                              ("an env key", {"env": {"API_TOKEN": "one", "NODE_DEBUG": "1"}}),
                              ("the command", {"command": "bun"})):
            with self.subTest(label):
                self.assertEqual(self.drift_after(change), "DRIFT")

    def test_env_values_and_the_url_query_are_not_pinned(self) -> None:
        for label, change in (("a rotated env value", {"env": {"API_TOKEN": "two"}}),
                              ("the url query", {"url": "https://api.example.invalid/v1/mcp?session=2"})):
            with self.subTest(label):
                self.assertEqual(self.drift_after(change), "ok")
        self.assertNotIn("one", json.dumps(pin.read_lock(str(self.lockfile))))


class TestUnpinnedWarning(SpecCase):
    def test_an_unpinned_package_warns_at_lock_time(self) -> None:
        self.config({"n": {"command": "npx", "args": ["-y", "acme-notes"]},
                     "t": {"command": "npx", "args": ["@acme/tool@latest"]},
                     "r": {"command": "npx", "args": ["acme-range@^1.2.0"]},
                     "u": {"command": "uvx", "args": ["acme-py"]},
                     "ok": {"command": "npx", "args": ["-y", "acme-pinned@1.2.3"]},
                     "okpy": {"command": "uvx", "args": ["acme-py2==0.4"]},
                     "url": {"command": "npx", "args": ["https://x.example.invalid/zq7tok/p.tgz"]}})
        code, err = self.lock()
        self.assertEqual(code, 0)
        lines = [line for line in err.splitlines() if "unpinned:" in line]
        for name, pkg in (("n", "acme-notes"), ("t", "@acme/tool"), ("r", "acme-range"), ("u", "acme-py")):
            self.assertIn(f"frisk lock: {self.cfg}::{name}: " + UNPINNED.format(pkg), lines)
        self.assertEqual(len(lines), 4)  # no line for exact pins or for a URL spec
        self.assertNotIn("zq7tok", err)


class TestRelativePaths(SpecCase):
    def setUp(self) -> None:
        super().setUp()
        (self.a / "skill").mkdir()
        (self.a / "skill" / "SKILL.md").write_text("A clean skill.\n", encoding="utf-8")
        self.config({"remote": {"url": "https://api.example.invalid/mcp"},
                     "pkg": {"command": "npx", "args": ["acme-notes@1.0.0"]}})
        os.chdir(self.a)
        code, _out, err = run(["lock", "skill", "--mcp-config", ".mcp.json"])
        self.assertEqual(code, 0, err)
        self.b = self.tmp / "b"
        self.b.mkdir()

    def test_a_lock_made_in_a_verifies_from_b(self) -> None:
        os.chdir(self.b)
        code, out, _ = run(["verify", "--lockfile", str(self.lockfile)])
        self.assertEqual(code, 0, out)
        self.assertIn("no drift", out)

    def test_a_copy_of_the_tree_verifies_and_catches_drift_in_the_copy(self) -> None:
        copy = self.tmp / "checkout"
        shutil.copytree(self.a, copy)
        os.chdir(self.b)
        self.assertEqual(run(["verify", "--lockfile", str(copy / ".frisk-lock.json")])[0], 0)
        (copy / "skill" / "SKILL.md").write_text("Changed.\n", encoding="utf-8")
        code, out, _ = run(["verify", "--lockfile", str(copy / ".frisk-lock.json")])
        self.assertEqual(code, 1)
        self.assertIn("~ changed: SKILL.md", out)

    def test_entries_keep_their_names_and_store_the_relative_path(self) -> None:
        lock = pin.read_lock(str(self.lockfile))
        self.assertEqual(lock["version"], 1)
        self.assertEqual(lock["entries"]["skill"]["recompute"], {"type": "target", "value": "skill",
                                                                   "relative": "skill"})
        self.assertEqual(lock["entries"][".mcp.json::pkg"]["recompute"]["relative"], ".mcp.json")


class TestVersion(SpecCase):
    def test_a_version_other_than_1_exits_2(self) -> None:
        for version in (2, 0, "1", True, None):
            with self.subTest(version=version):
                doc: dict = {"entries": {}}
                if version is not None:
                    doc["version"] = version
                self.lockfile.write_text(json.dumps(doc), encoding="utf-8")
                code, out, err = run(["verify", "--lockfile", str(self.lockfile)])
                self.assertEqual((code, out), (2, ""))
                self.assertIn("unsupported lockfile version", err)
                self.assertEqual(len(err.splitlines()), 1)

    def test_version_1_still_reads(self) -> None:
        self.lockfile.write_text(json.dumps({"version": 1, "entries": {}}), encoding="utf-8")
        self.assertEqual(run(["verify", "--lockfile", str(self.lockfile)])[0], 0)


if __name__ == "__main__":
    unittest.main()
