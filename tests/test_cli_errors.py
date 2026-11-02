"""FR-E5 t6: CLI and source errors end in one line and exit 2, never a traceback; git never
waits for a password; frisk verify counts entries it could not verify apart from drift.

git is never run: frisk.sources.subprocess.run is replaced by a recorder. Hosts use the
.invalid TLD, and HOME is a temp directory.
Run: PYTHONPATH=src python3 -B -m unittest discover -s tests
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from _home import fake_home
from frisk import pin
from frisk.cli import main

URL = "https://git.example.invalid/acme/tool.git"


class GitRecorder:
    """Stands in for subprocess.run in frisk.sources: records each call, then fails the
    clone (exit code 128) or, with `hang`, times out as a hung clone does."""

    def __init__(self, hang: bool = False) -> None:
        self.calls: list[tuple[list[str], dict]] = []
        self.hang = hang

    def __call__(self, argv: list[str], **kwargs: object) -> subprocess.CompletedProcess:
        self.calls.append((argv, kwargs))
        if self.hang:
            raise subprocess.TimeoutExpired(argv, 120)
        return subprocess.CompletedProcess(argv, 128, "", "fatal: repository not found\n")


def run(argv: list[str], git: GitRecorder | None = None) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with mock.patch("frisk.sources.subprocess.run", git or GitRecorder()), \
            mock.patch("frisk.report._USE_COLOR", False), \
            contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class CliCase(unittest.TestCase):
    def setUp(self) -> None:
        fake_home(self)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.lockfile = str(self.tmp / "lock.json")

    def assert_one_line(self, err: str, starts: str) -> None:
        self.assertNotIn("Traceback", err)
        self.assertEqual(len(err.splitlines()), 1, err)
        self.assertTrue(err.startswith(starts), err)


class TestGit(CliCase):
    def test_git_gets_no_stdin_no_prompt_and_an_argv_list(self) -> None:
        git = GitRecorder()
        with mock.patch.dict(os.environ, {"FRISK_TEST_KEPT": "1"}):
            code, _, err = run([URL], git)
        self.assertEqual(code, 2)
        ((argv, kwargs),) = git.calls
        self.assertEqual(argv[:5], ["git", "clone", "--depth", "1", "--quiet"])
        self.assertIs(kwargs["stdin"], subprocess.DEVNULL)
        self.assertNotIn("shell", kwargs)
        env = kwargs["env"]
        assert isinstance(env, dict)
        self.assertEqual(env["GIT_TERMINAL_PROMPT"], "0")
        self.assertEqual(env["FRISK_TEST_KEPT"], "1")  # the rest of the environment is kept
        self.assert_one_line(err, "frisk: git clone failed")

    def test_a_clone_that_times_out_exits_2_with_one_line(self) -> None:
        for argv in ([URL], ["--json", URL], ["lock", URL, "--lockfile", self.lockfile]):
            with self.subTest(argv=argv[:-1]):
                code, out, err = run(argv, GitRecorder(hang=True))
                self.assertEqual((code, out), (2, ""))
                self.assert_one_line(err, "frisk")
                self.assertIn("git clone timed out after 120 s", err)


class TestConfigs(CliCase):
    def test_list_shaped_configs_exit_2_with_one_line(self) -> None:
        for label, data in (("top level", [{"command": "node"}]), ("mcpServers", {"mcpServers": [{"command": "node"}]}),
                            ("projects", {"projects": [{"mcpServers": {}}]})):
            cfg = self.tmp / f"{label.replace(' ', '-')}.json"
            cfg.write_text(json.dumps(data), encoding="utf-8")
            for argv in (["--mcp-config", str(cfg)], ["lock", "--mcp-config", str(cfg), "--lockfile", self.lockfile]):
                with self.subTest(label, argv=argv[0]):
                    code, out, err = run(argv)
                    self.assertEqual((code, out), (2, ""))
                    self.assert_one_line(err, "frisk")
                    self.assertIn("is not a JSON object", err)

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root reads a mode-000 file")
    def test_an_unreadable_file_on_lock_exits_2_with_one_line(self) -> None:
        secret = self.tmp / "tool.py"
        secret.write_text("print(1)\n", encoding="utf-8")
        secret.chmod(0)
        self.addCleanup(secret.chmod, 0o600)
        code, out, err = run(["lock", str(secret), "--lockfile", self.lockfile])
        self.assertEqual((code, out), (2, ""))
        self.assert_one_line(err, "frisk lock: ")
        self.assertIn("Permission denied", err)
        self.assertFalse(Path(self.lockfile).exists())


class TestVerify(CliCase):
    def lock(self, *targets: str) -> None:
        self.assertEqual(run(["lock", *targets, "--lockfile", self.lockfile])[0], 0)

    def skill(self, name: str) -> Path:
        d = self.tmp / name
        d.mkdir()
        (d / "SKILL.md").write_text("Make a table of contents.\n", encoding="utf-8")
        return d

    def test_an_unreachable_target_is_not_reported_as_drift(self) -> None:
        gone = self.skill("gone")
        self.lock(str(gone))
        shutil.rmtree(gone)
        code, out, err = run(["verify", "--lockfile", self.lockfile])
        self.assertEqual((code, err), (1, ""))
        self.assertIn(f"  [error] {gone}  not a path or recognizable git URL", out)
        self.assertIn("verify: could not verify 1 entry  (0 of 1 entries changed)", out)
        self.assertNotIn("DRIFT DETECTED", out)

    def test_an_unreachable_git_target_is_counted_apart_from_drift(self) -> None:
        kept = self.skill("kept")
        lock = {"version": 1, "entries": {
            URL: {"digest": "x", "files": {}, "kind": "source", "recompute": {"type": "target", "value": URL}}}}
        pin.write_lock(lock, self.lockfile)
        code, out, _ = run(["verify", "--lockfile", self.lockfile])
        self.assertEqual(code, 1)
        self.assertIn("could not verify 1 entry", out)
        both = pin.build_lock([str(kept)], [])
        both["entries"].update(lock["entries"])
        pin.write_lock(both, self.lockfile)
        (kept / "SKILL.md").write_text("changed\n", encoding="utf-8")
        code, out, _ = run(["verify", "--lockfile", self.lockfile])
        self.assertEqual(code, 1)
        self.assertIn("verify: DRIFT DETECTED  (1 of 2 entries changed; could not verify 1 entry)", out)

    def test_a_lockfile_of_the_wrong_shape_exits_2_with_one_line(self) -> None:
        for body in ("[]", '{"entries": []}', '{"version": 1}', '"text"'):
            with self.subTest(body=body):
                Path(self.lockfile).write_text(body, encoding="utf-8")
                code, out, err = run(["verify", "--lockfile", self.lockfile])
                self.assertEqual((code, out), (2, ""))
                self.assert_one_line(err, "frisk verify: ")
                self.assertIn("not a frisk lockfile", err)

    def test_a_malformed_entry_is_unverified_and_the_others_are_still_checked(self) -> None:
        kept = self.skill("kept")
        lock = pin.build_lock([str(kept)], [])
        lock["entries"].update({"a": 5, "b": {"recompute": {"type": "target", "value": str(kept)}},
                                "c": {"digest": "x", "recompute": {"type": "server"}}})
        pin.write_lock(lock, self.lockfile)
        code, out, err = run(["verify", "--lockfile", self.lockfile])
        self.assertEqual((code, err), (1, ""))
        self.assertIn(f"  [ok   ] {kept}", out)
        self.assertIn("  [error] a  not a valid lockfile entry", out)
        self.assertIn("  [error] b  not a valid lockfile entry", out)
        self.assertIn("  [error] c  ", out)
        self.assertIn("verify: could not verify 3 entries  (0 of 4 entries changed)", out)
        report = json.loads(run(["verify", "--json", "--lockfile", self.lockfile])[1])
        self.assertEqual([r["status"] for r in report], ["ok", "error", "error", "error"])


if __name__ == "__main__":
    unittest.main()
