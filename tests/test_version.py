"""FR-E7 t2 (F4.01): one version, and a CHANGELOG built from the changes/ fragments.

The version is written only in src/frisk/__init__.py; pyproject.toml reads it through hatch.
`frisk --version` prints it. Folded fragments are gone from changes/ and are in CHANGELOG.md;
a fragment added later (not yet folded) is allowed.
Run: PYTHONPATH=src python3 -B -m unittest discover -s tests
"""
from __future__ import annotations

import re
import unittest

from _pyproject import load_pyproject
from _subproc import REPO, run_cli
from frisk import __version__

CHANGES = REPO / "changes"
# hatch's default version pattern for [tool.hatch.version] path.
HATCH_PATTERN = re.compile(r"""(?im)^(?:__version__|VERSION) *= *(['"])v?(?P<version>.+?)\1""")


def folded() -> list[str]:
    """The stems listed under '## Folded' in changes/README.md."""
    text = (CHANGES / "README.md").read_text(encoding="utf-8")
    section = text.split("\n## Folded\n", 1)[1]
    return re.findall(r"^- (\S+)$", section, re.MULTILINE)


class TestVersion(unittest.TestCase):
    def test_version_flag_prints_dunder_version(self) -> None:
        r = run_cli(["--version"])
        self.assertEqual(r.returncode, 0)
        self.assertEqual(r.stdout.decode("utf-8"), f"frisk {__version__}\n")

    def test_pyproject_reads_the_version_from_init(self) -> None:
        data = load_pyproject()
        self.assertNotIn("version", data["project"])
        self.assertEqual(data["project"]["dynamic"], ["version"])
        path = data["tool"]["hatch"]["version"]["path"]
        self.assertEqual(path, "src/frisk/__init__.py")
        match = HATCH_PATTERN.search((REPO / path).read_text(encoding="utf-8"))
        self.assertIsNotNone(match)
        assert match is not None
        self.assertEqual(match.group("version"), __version__)

    def test_no_other_file_states_the_version(self) -> None:
        text = (REPO / "pyproject.toml").read_text(encoding="utf-8")
        self.assertNotRegex(text, r"(?m)^version\s*=")


class TestChangelog(unittest.TestCase):
    def setUp(self) -> None:
        self.text = (REPO / "CHANGELOG.md").read_text(encoding="utf-8")

    def test_sections(self) -> None:
        heads = re.findall(r"^## (.+)$", self.text, re.MULTILINE)
        self.assertEqual(heads, ["0.3.0 — Unreleased", "0.2.0 — 2026-07-02 — not released to PyPI",
                                 "0.1.0 — 2026-06-24 — on PyPI"])

    def test_folded_fragments_are_deleted_and_in_the_changelog(self) -> None:
        stems = folded()
        self.assertTrue(stems)
        self.assertEqual(len(stems), len(set(stems)))
        for stem in stems:
            with self.subTest(stem):
                self.assertFalse((CHANGES / f"{stem}.md").exists())
                self.assertIn(f"<!-- changes/{stem}.md, added in ", self.text)

    def test_a_fragment_still_in_changes_is_not_yet_folded(self) -> None:
        stems = set(folded())
        for path in CHANGES.glob("*.md"):
            if path.name != "README.md":
                with self.subTest(path.name):
                    self.assertNotIn(path.stem, stems)
                    self.assertNotIn(f"<!-- changes/{path.stem}.md,", self.text)


if __name__ == "__main__":
    unittest.main()
