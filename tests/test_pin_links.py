"""FR-E6 H1.3b: frisk lock pins a symlink by where it points, never by its target's bytes.

A link (to a file or a directory) is hashed by os.readlink, so content outside the locked
tree is never read and a change there is not drift, while retargeting the link is, even to a
file with the same bytes. A FIFO in the tree does not hang lock. Temp trees only.
Run: PYTHONPATH=src python3 -B -m unittest discover -s tests
"""
from __future__ import annotations

import hashlib
import os
import tempfile
import threading
import unittest
from pathlib import Path

from frisk import pin


class LinkCase(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = Path(os.path.realpath(tmp.name))
        self.tree = base / "tree"
        self.tree.mkdir()
        (self.tree / "SKILL.md").write_text("A clean skill.\n", encoding="utf-8")
        self.outside = base / "outside"
        self.outside.mkdir()
        self.a = self.outside / "a.txt"
        self.a.write_text("first\n", encoding="utf-8")
        self.b = self.outside / "b.txt"
        self.b.write_text("first\n", encoding="utf-8")  # the same bytes as a.txt

    def verify(self, lock: dict) -> dict:
        (record,) = pin.verify_lock(lock)
        return record

    def retarget(self, link: Path, target: Path) -> None:
        os.remove(link)
        os.symlink(target, link, target_is_directory=target.is_dir())


class TestLinkedFiles(LinkCase):
    def test_outside_content_is_not_pinned(self) -> None:
        (self.tree / "notes.md").symlink_to(self.a)
        lock = pin.build_lock([str(self.tree)], [])
        self.a.write_text("changed outside the tree\n", encoding="utf-8")
        self.assertEqual(self.verify(lock)["status"], "ok")

    def test_retargeting_a_link_is_drift(self) -> None:
        link = self.tree / "notes.md"
        link.symlink_to(self.a)
        lock = pin.build_lock([str(self.tree)], [])
        self.retarget(link, self.b)
        record = self.verify(lock)
        self.assertEqual((record["status"], record["changed"]), ("DRIFT", ["notes.md"]))

    def test_retargeting_a_directory_link_is_drift(self) -> None:
        other = self.outside / "other"
        other.mkdir()
        link = self.tree / "vendor"
        link.symlink_to(self.outside, target_is_directory=True)
        lock = pin.build_lock([str(self.tree)], [])
        self.assertEqual(self.verify(lock)["status"], "ok")
        self.retarget(link, other)
        self.assertEqual(self.verify(lock)["changed"], ["vendor"])

    def test_a_single_file_target_that_is_a_link(self) -> None:
        link = self.tree / "notes.md"
        link.symlink_to(self.a)
        lock = pin.build_lock([str(link)], [])
        self.a.write_text("changed outside the tree\n", encoding="utf-8")
        self.assertEqual(self.verify(lock)["status"], "ok")
        self.retarget(link, self.b)
        self.assertEqual(self.verify(lock)["status"], "DRIFT")

    def test_a_tree_without_links_pins_as_before(self) -> None:
        (self.tree / "sub").mkdir()
        (self.tree / "sub" / "x.py").write_text("print(1)\n", encoding="utf-8")
        (self.tree / "sub-a.md").write_text("b\n", encoding="utf-8")
        fp = pin.fingerprint_path(self.tree)
        # the digest frisk has always taken: sha256 over (relative path, file hash), in Path order
        files = sorted(p for p in self.tree.rglob("*") if p.is_file())
        overall = hashlib.sha256()
        for p in files:
            rel = str(p.relative_to(self.tree))
            overall.update(rel.encode())
            overall.update(pin._sha(p.read_bytes()).encode())
        self.assertEqual(fp["digest"], overall.hexdigest())


@unittest.skipUnless(hasattr(os, "mkfifo"), "needs os.mkfifo")
class TestSpecialFiles(LinkCase):
    def test_a_fifo_does_not_hang_lock(self) -> None:
        os.mkfifo(self.tree / "pipe")
        box: list[dict] = []
        worker = threading.Thread(target=lambda: box.append(pin.build_lock([str(self.tree)], [])), daemon=True)
        worker.start()
        worker.join(timeout=5)
        self.assertFalse(worker.is_alive(), "frisk lock did not finish within 5 s")
        (entry,) = box[0]["entries"].values()
        self.assertEqual(sorted(entry["files"]), ["SKILL.md"])


if __name__ == "__main__":
    unittest.main()
