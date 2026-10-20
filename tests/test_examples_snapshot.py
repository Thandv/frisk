"""Findings snapshot for examples/*/: pins TODAY's (path, line, rule, severity) for every finding.

Scope is each directory directly under examples/ (examples/continuous-verify.yml is a
workflow template, not agent content, and is out of scope). Paths are relative to the
repo root, so the result does not depend on the working directory.

Each snapshot entry carries `expected_change`: null, or the epic that is expected to
change that entry. Today one entry is marked "FR-E2": a finding inside a markdown code
fence is reported at its line within the fence, so the pipe-to-shell installer in
examples/malicious-skill/SKILL.md shows as line 1 although it sits on file line 11.
FR-E2 fixes that and updates the snapshot.
Run: PYTHONPATH=src python3 -m unittest discover -s tests
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any

from frisk.engine import scan_path

REPO = Path(__file__).resolve().parent.parent
EXAMPLES = REPO / "examples"
SNAPSHOT = REPO / "tests" / "snapshots" / "examples_findings.json"
KEY_FIELDS = ("path", "line", "rule", "severity")

Row = tuple[str, int, str, str]


def live_findings() -> list[Row]:
    """Scan every examples/*/ directory; return sorted (path, line, rule, severity)."""
    rows: list[Row] = []
    for directory in sorted(p for p in EXAMPLES.iterdir() if p.is_dir()):
        for f in scan_path(directory, REPO):
            rows.append((Path(f.path).as_posix(), f.line, f.rule, f.severity))
    return sorted(rows)


def load_snapshot() -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    return entries


def snapshot_rows(entries: list[dict[str, Any]]) -> list[Row]:
    return [(e["path"], e["line"], e["rule"], e["severity"]) for e in entries]


class TestExamplesSnapshot(unittest.TestCase):
    def test_live_scan_matches_snapshot_exactly(self) -> None:
        self.assertEqual(live_findings(), snapshot_rows(load_snapshot()))

    def test_independent_of_working_directory(self) -> None:
        expected = live_findings()
        with tempfile.TemporaryDirectory() as d:
            here = os.getcwd()
            os.chdir(d)
            try:
                self.assertEqual(live_findings(), expected)
            finally:
                os.chdir(here)

    def test_snapshot_is_sorted_and_well_formed(self) -> None:
        entries = load_snapshot()
        rows = snapshot_rows(entries)
        self.assertEqual(rows, sorted(rows))
        self.assertEqual(len(rows), len(set(rows)))
        for e in entries:
            self.assertIn("expected_change", e)
            self.assertIn(e["expected_change"], (None, "FR-E2"))
            self.assertLessEqual(set(e), set(KEY_FIELDS) | {"expected_change", "note"})

    def test_fence_relative_line_is_recorded_for_fr_e2(self) -> None:
        marked = [e for e in load_snapshot() if e["expected_change"] == "FR-E2"]
        self.assertEqual(snapshot_rows(marked),
                         [("examples/malicious-skill/SKILL.md", 1, "rce.pipe_installer", "block")])
        self.assertIn("file line 11", marked[0]["note"])


if __name__ == "__main__":
    unittest.main()
