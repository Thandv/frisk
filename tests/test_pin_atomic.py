"""FR-E5 t8: the lockfile is written atomically (temp file in the same directory, fsync,
os.replace), so a failure part way never leaves a truncated lockfile.
Run: PYTHONPATH=src python3 -B -m unittest discover -s tests
"""
from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from frisk import pin

LOCK = {"version": 1, "entries": {"skill": {"digest": "a" * 64, "files": {"SKILL.md": "b" * 64},
                                             "kind": "source", "recompute": {"type": "target", "value": "skill"}}}}


class TestAtomicWrite(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.path = self.dir / "lock.json"

    def test_a_failure_before_the_replace_keeps_the_old_bytes_and_leaves_no_temp_file(self) -> None:
        self.path.write_bytes(b'{"version": 1, "entries": {}}')
        old = self.path.read_bytes()
        for fault in ("os.replace", "os.fsync"):
            with self.subTest(fault=fault), mock.patch(fault, side_effect=OSError(28, "No space left on device")), \
                    self.assertRaises(OSError):
                pin.write_lock(LOCK, str(self.path))
            self.assertEqual(self.path.read_bytes(), old)
            self.assertEqual(sorted(p.name for p in self.dir.iterdir()), ["lock.json"])

    def test_the_temp_file_is_fsynced_in_the_target_directory_then_replaced(self) -> None:
        events: list[str] = []
        real_fsync, real_replace = os.fsync, os.replace

        def fsync(fd: int) -> None:
            events.append("fsync")
            real_fsync(fd)

        def replace(src: str, dst: object) -> None:
            events.append("replace")
            self.assertEqual(Path(src).parent, self.dir)
            self.assertEqual(json.loads(Path(src).read_text(encoding="utf-8")), LOCK)
            real_replace(src, dst)

        with mock.patch("os.fsync", fsync), mock.patch("os.replace", replace):
            pin.write_lock(LOCK, str(self.path))
        self.assertEqual(events, ["fsync", "replace"])

    def test_round_trip_bytes_and_mode_are_unchanged(self) -> None:
        pin.write_lock(LOCK, str(self.path))
        self.assertEqual(self.path.read_text(encoding="utf-8"), json.dumps(LOCK, indent=2))
        self.assertEqual(pin.read_lock(str(self.path)), LOCK)
        umask = os.umask(0)
        os.umask(umask)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o666 & ~umask)
        self.path.chmod(0o640)
        pin.write_lock(LOCK, str(self.path))
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o640)
        self.assertEqual(sorted(p.name for p in self.dir.iterdir()), ["lock.json"])


if __name__ == "__main__":
    unittest.main()
