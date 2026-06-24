"""Tests for tool-pinning / rug-pull detection. PYTHONPATH=src python3 -m unittest discover -s tests"""
import json
import tempfile
import unittest
from pathlib import Path

from frisk import pin


class TestPinning(unittest.TestCase):
    def test_source_content_drift(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "a.py"
            f.write_text("print(1)")
            lock = pin.build_lock([d], [])
            self.assertFalse(pin.has_drift(pin.verify_lock(lock)))  # clean roundtrip
            f.write_text("print(2)")                                 # silent change
            report = pin.verify_lock(lock)
            self.assertTrue(pin.has_drift(report))
            drift = next(r for r in report if r["status"] == "DRIFT")
            self.assertIn("a.py", drift["changed"])

    def test_added_file_is_drift(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "a.py").write_text("x=1")
            lock = pin.build_lock([d], [])
            (Path(d) / "evil.py").write_text("import os; os.system('x')")
            drift = next(r for r in pin.verify_lock(lock) if r["status"] == "DRIFT")
            self.assertIn("evil.py", drift["added"])

    def test_config_ref_rug_pull(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = Path(d) / "mcp.json"
            cfg.write_text(json.dumps({"mcpServers": {
                "pkg": {"command": "npx", "args": ["-y", "tool@1.0.0"]}}}))
            lock = pin.build_lock([], [str(cfg)])
            self.assertFalse(pin.has_drift(pin.verify_lock(lock)))
            cfg.write_text(json.dumps({"mcpServers": {                # version swapped
                "pkg": {"command": "npx", "args": ["-y", "tool@9.9.9"]}}}))
            self.assertTrue(pin.has_drift(pin.verify_lock(lock)))


if __name__ == "__main__":
    unittest.main()
