"""FR-E8 t1 (F4.05): README.md's demo blocks are real output of the code as it is now.

Each `<!-- frisk-demo: NAME -->` block must equal what scripts/gen_readme_demo.py renders
from a fresh run in a temp sandbox (temp working directory and HOME, no network), so a
changed rule description, verdict line or audit format fails here until the README is
regenerated with `python3 scripts/gen_readme_demo.py`. The test writes nothing into the repo.
Run: PYTHONPATH=src python3 -B -m unittest discover -s tests
"""
from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
from unittest import mock

REPO = Path(__file__).resolve().parent.parent


def load_script(name: str) -> ModuleType:
    """scripts/<name>.py as a module, without writing its bytecode into the repo."""
    spec = importlib.util.spec_from_file_location(name, REPO / "scripts" / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # dataclasses look their module up there
    with mock.patch.object(sys, "dont_write_bytecode", True):
        spec.loader.exec_module(module)
    return module


gen = load_script("gen_readme_demo")


class TestReadmeDemos(unittest.TestCase):
    def setUp(self) -> None:
        self.readme = gen.README.read_text(encoding="utf-8")

    def test_every_demo_block_is_real_output(self) -> None:
        fresh = gen.render(self.readme)
        for m_now, m_fresh in zip(gen.BLOCK.finditer(self.readme), gen.BLOCK.finditer(fresh)):
            with self.subTest(demo=m_now.group(2)):
                self.assertEqual(m_now.group(3), m_fresh.group(3),
                                 "stale README demo block: run python3 scripts/gen_readme_demo.py")
        self.assertEqual(self.readme, fresh)

    def test_each_demo_appears_once(self) -> None:
        names = [m.group(2) for m in gen.BLOCK.finditer(self.readme)]
        self.assertEqual(sorted(names), sorted(gen.DEMOS))

    def test_a_changed_rule_description_makes_a_block_stale(self) -> None:
        # The generator runs a copy of src/ and examples/ in a temp directory, so the
        # description is changed there, never in the repo.
        with tempfile.TemporaryDirectory() as tmp:
            for part in ("src", "examples"):
                shutil.copytree(REPO / part, Path(tmp) / part, ignore=shutil.ignore_patterns("__pycache__"))
            rules = Path(tmp) / "src" / "frisk" / "rules.py"
            text = rules.read_text(encoding="utf-8")
            old = "\"prompt-injection: 'ignore previous instructions'\""
            self.assertEqual(text.count(old), 1)
            rules.write_text(text.replace(old, '"prompt-injection: reworded"'), encoding="utf-8")
            with mock.patch.object(gen, "REPO", Path(tmp)):
                fresh = gen.render(self.readme)
        self.assertNotEqual(fresh, self.readme)
        self.assertIn("prompt-injection: reworded", fresh)

    def test_an_unknown_demo_name_is_an_error(self) -> None:
        with self.assertRaises(ValueError):
            gen.render("<!-- frisk-demo: nope -->\n```\n```\n<!-- /frisk-demo -->\n")

    def test_check_mode_passes_on_a_fresh_readme(self) -> None:
        r = subprocess.run([sys.executable, "-B", str(REPO / "scripts" / "gen_readme_demo.py"), "--check"],
                           capture_output=True, text=True, timeout=300, check=False)
        self.assertEqual((r.returncode, r.stderr), (0, ""))


if __name__ == "__main__":
    unittest.main()
