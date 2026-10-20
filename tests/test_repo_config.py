"""Pins the pytest collection config. Run: PYTHONPATH=src python3 -m unittest discover -s tests"""
from __future__ import annotations

import sys
import unittest

from _pyproject import PYPROJECT, load_pyproject, parse_minimal

SAMPLE = """
# leading comment
[project]
name = "demo"          # trailing comment
dependencies = []
authors = [{ name = "Someone" }]
classifiers = [
  "A :: B",   # a comment with a ] bracket
  "C # not a comment",
]

[tool.demo.inner]
flag = true
off = false
count = 3

[[tool.demo.overrides]]
module = ["demo.*"]
strict = true
"""


class TestPytestConfig(unittest.TestCase):
    def setUp(self) -> None:
        self.ini = load_pyproject()["tool"]["pytest"]["ini_options"]

    def test_collects_only_tests_dir(self) -> None:
        self.assertEqual(self.ini["testpaths"], ["tests"])
        self.assertEqual(self.ini["pythonpath"], ["src"])

    def test_never_recurses_into_corpus_or_examples(self) -> None:
        self.assertIn("corpus", self.ini["norecursedirs"])
        self.assertIn("examples", self.ini["norecursedirs"])

    def test_no_cache_dir_written(self) -> None:
        self.assertIn("-p no:cacheprovider", self.ini["addopts"])


class TestMinimalParser(unittest.TestCase):
    def test_parses_supported_subset(self) -> None:
        data = parse_minimal(SAMPLE)
        self.assertEqual(data["project"]["name"], "demo")
        self.assertEqual(data["project"]["dependencies"], [])
        self.assertEqual(data["project"]["classifiers"], ["A :: B", "C # not a comment"])
        self.assertEqual(data["tool"]["demo"]["inner"], {"flag": True, "off": False, "count": 3})
        self.assertEqual(data["tool"]["demo"]["overrides"], [{"module": ["demo.*"], "strict": True}])

    def test_skips_inline_tables_instead_of_guessing(self) -> None:
        self.assertNotIn("authors", parse_minimal(SAMPLE)["project"])

    @unittest.skipUnless(sys.version_info >= (3, 11), "tomllib is stdlib from 3.11")
    def test_agrees_with_tomllib_on_the_real_tool_tables(self) -> None:
        import tomllib  # stdlib only from 3.11

        with PYPROJECT.open("rb") as fh:
            real = tomllib.load(fh)
        minimal = parse_minimal(PYPROJECT.read_text(encoding="utf-8"))
        self.assertEqual(minimal["tool"], real["tool"])
        self.assertEqual(minimal["project"].get("optional-dependencies"),
                         real["project"].get("optional-dependencies"))


if __name__ == "__main__":
    unittest.main()
