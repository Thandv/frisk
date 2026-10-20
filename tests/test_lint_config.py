"""Pins the lint/type/test tool config and the dev extras. Run: PYTHONPATH=src python3 -m unittest discover -s tests"""
from __future__ import annotations

import unittest

from _pyproject import load_pyproject


class TestLintConfig(unittest.TestCase):
    def setUp(self) -> None:
        self.data = load_pyproject()
        self.tool = self.data["tool"]

    def test_tool_sections_exist(self) -> None:
        self.assertIn("ruff", self.tool)
        self.assertIn("mypy", self.tool)
        self.assertIn("ini_options", self.tool["pytest"])

    def test_ruff_targets_the_runtime_floor(self) -> None:
        self.assertEqual(self.tool["ruff"]["target-version"], "py39")
        self.assertEqual(self.tool["ruff"]["lint"]["select"], ["E", "F", "W", "B", "UP", "SIM"])

    def test_mypy_requires_typed_defs_in_frisk(self) -> None:
        self.assertIs(self.tool["mypy"]["check_untyped_defs"], True)
        self.assertIs(self.tool["mypy"]["warn_unused_ignores"], True)
        frisk = [o for o in self.tool["mypy"]["overrides"] if o["module"] == ["frisk.*"]]
        self.assertEqual(len(frisk), 1)
        self.assertIs(frisk[0]["disallow_untyped_defs"], True)

    def test_extras_carry_the_tools_and_runtime_stays_stdlib_only(self) -> None:
        project = self.data["project"]
        self.assertEqual(project["dependencies"], [])
        extras = project["optional-dependencies"]
        self.assertEqual(extras["test"], ["pytest"])
        self.assertEqual(set(extras["dev"]), {"pytest", "ruff", "mypy"})


if __name__ == "__main__":
    unittest.main()
