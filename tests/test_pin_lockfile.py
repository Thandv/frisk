"""A lockfile inside a directory it pins is not part of what it pins (FR-E9 review).

`frisk lock .` then `frisk verify` (examples/continuous-verify.yml's flow) is no drift, and
so is a local server whose directory holds the lockfile. Only the lockfile itself, by its
resolved path, is left out: a file of the same name anywhere else in the tree, or a link at
the lockfile's path, is still pinned. A lock an older frisk wrote with the lockfile in the
pinned tree reports DRIFT once (`- removed: .frisk-lock.json`) and is clean after a re-lock.
Temp trees only, run as a user runs frisk (python -m frisk.cli).
Run: PYTHONPATH=src python3 -B -m unittest discover -s tests
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from _subproc import run_cli
from frisk import pin


class LockfileInTree(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(os.path.realpath(tmp.name))
        self.proj = self.base / "proj"
        (self.proj / "sub").mkdir(parents=True)
        (self.proj / "server.py").write_text("print('hi')\n", encoding="utf-8")
        (self.proj / "sub" / "a.py").write_text("x = 1\n", encoding="utf-8")

    def frisk(self, *args: str, cwd: Path | None = None) -> tuple[int, str]:
        r = run_cli(list(args), cwd=cwd or self.proj)
        return r.returncode, (r.stdout + r.stderr).decode("utf-8")

    def assert_clean(self, *verify_args: str, cwd: Path | None = None) -> None:
        rc, out = self.frisk("verify", *verify_args, cwd=cwd)
        self.assertEqual(rc, 0, out)
        self.assertIn("verify: no drift", out)

    def test_lock_dot_then_verify_is_clean_and_stays_clean_after_a_relock(self) -> None:
        self.assertEqual(self.frisk("lock", ".")[0], 0)
        self.assert_clean()
        self.assertEqual(self.frisk("lock", ".")[0], 0)  # the old lockfile is in the tree now
        self.assert_clean()
        entry = json.loads((self.proj / pin.LOCK_DEFAULT).read_text(encoding="utf-8"))["entries"]["."]
        self.assertEqual(sorted(entry["files"]), ["server.py", "sub/a.py"])

    def test_an_explicit_lockfile_in_a_subdirectory_and_from_another_directory(self) -> None:
        self.assertEqual(self.frisk("lock", ".", "--lockfile", "sub/l.json")[0], 0)
        self.assert_clean("--lockfile", "sub/l.json")
        self.assertEqual(self.frisk("lock", "proj", "--lockfile", "proj/l.json", cwd=self.base)[0], 0)
        self.assert_clean("--lockfile", "l.json")  # from inside the tree: the target is stored relative
        self.assert_clean("--lockfile", "proj/l.json", cwd=self.base)

    def test_a_local_server_whose_directory_holds_the_lockfile(self) -> None:
        cfg = self.proj / ".mcp.json"
        server = {"command": "python3", "args": [str(self.proj / "server.py")]}
        cfg.write_text(json.dumps({"mcpServers": {"s": server}}), encoding="utf-8")
        self.assertEqual(self.frisk("lock", ".", "--mcp-config", ".mcp.json")[0], 0)
        self.assert_clean()

    def test_the_rest_of_the_tree_is_still_pinned(self) -> None:
        self.assertEqual(self.frisk("lock", ".")[0], 0)
        (self.proj / "server.py").write_text("print('changed')\n", encoding="utf-8")
        rc, out = self.frisk("verify")
        self.assertEqual(rc, 1, out)
        self.assertIn("~ changed: server.py", out)

    def test_nothing_else_hides_under_the_lockfiles_name(self) -> None:
        self.assertEqual(self.frisk("lock", ".")[0], 0)
        (self.proj / "sub" / pin.LOCK_DEFAULT).write_text("import os\n", encoding="utf-8")  # same name, elsewhere
        os.symlink(pin.LOCK_DEFAULT, self.proj / "link.json")  # a link to the lockfile
        rc, out = self.frisk("verify")
        self.assertEqual(rc, 1, out)
        self.assertIn(f"+ added:   sub/{pin.LOCK_DEFAULT}", out)
        self.assertIn("+ added:   link.json", out)

    def test_a_link_at_the_lockfiles_path_is_pinned(self) -> None:
        (self.proj / "real.json").write_text("{}", encoding="utf-8")
        lockfile = self.proj / "l.json"
        lock = pin.build_lock([str(self.proj)], [], lockfile=lockfile)
        os.symlink("real.json", lockfile)  # what sits at the lockfile's path is a link, not the lockfile
        (record,) = pin.verify_lock(lock, lockfile=lockfile)
        self.assertEqual(record["status"], "DRIFT")
        self.assertEqual(record["added"], ["l.json"])

    def test_a_lock_written_with_the_lockfile_in_the_tree_drifts_once(self) -> None:
        self.assertEqual(self.frisk("lock", ".")[0], 0)
        cwd = os.getcwd()
        os.chdir(self.proj)
        try:
            old = pin.build_lock(["."], [], self.proj)  # as an older frisk wrote it: the lockfile pinned
        finally:
            os.chdir(cwd)
        self.assertIn(pin.LOCK_DEFAULT, old["entries"]["."]["files"])
        pin.write_lock(old, str(self.proj / pin.LOCK_DEFAULT))
        rc, out = self.frisk("verify")
        self.assertEqual(rc, 1, out)
        self.assertIn(f"- removed: {pin.LOCK_DEFAULT}", out)
        self.assertEqual(self.frisk("lock", ".")[0], 0)
        self.assert_clean()


if __name__ == "__main__":
    unittest.main()
