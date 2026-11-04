"""FR-E7 t5 (F4.02): the CI matrix and gates, read from .github/workflows/ci.yml as text.

Python 3.9 to 3.14 on ubuntu-latest plus one macos-latest job, each running scripts/verify.sh
and pytest; a blocking lint job with ruff, mypy on src and a coverage report (no floor yet:
the owner sets it from the first CI number); contents: read; action refs are tags, never
SHAs. That the run is green is checked on GitHub after the owner pushes, not here. Also
scripts/verify.sh's FRISK_VERIFY_PYTHONS override, run on missing paths only (no suite).
Run: PYTHONPATH=src python3 -B -m unittest discover -s tests
"""
from __future__ import annotations

import re
import subprocess
import unittest

from _subproc import REPO
from test_ci_workflow import job, steps

CI = REPO / ".github" / "workflows" / "ci.yml"
VERIFY = REPO / "scripts" / "verify.sh"


class TestMatrix(unittest.TestCase):
    def setUp(self) -> None:
        self.text = CI.read_text(encoding="utf-8")
        self.test = job(self.text, "test")
        self.lint = job(self.text, "lint")

    def test_python_3_9_to_3_14_on_ubuntu_and_one_macos_job(self) -> None:
        self.assertIn("    runs-on: ${{ matrix.os }}\n", self.test)
        self.assertIn('        python-version: ["3.9", "3.10", "3.11", "3.12", "3.13", "3.14"]\n', self.test)
        self.assertIn("        os: [ubuntu-latest]\n", self.test)
        self.assertIn('          - os: macos-latest\n            python-version: "3.13"\n', self.test)
        self.assertIn("      fail-fast: false\n", self.test)

    def test_each_leg_runs_verify_sh_and_pytest(self) -> None:
        runs = [s for s in steps(self.test) if "run:" in s]
        self.assertTrue(any('FRISK_VERIFY_PYTHONS="$(command -v python)" bash scripts/verify.sh' in s and
                            'FRISK_MIN_PYTHONS: "1"' in s for s in runs))
        self.assertTrue(any(s.strip() == "- run: python -m pytest -q" for s in runs))

    def test_lint_is_blocking_with_ruff_mypy_and_a_coverage_report(self) -> None:
        for line in ("      - run: ruff check\n", "      - run: mypy src\n", "      - run: coverage run -m pytest -q\n",
                     "      - run: coverage report --include='src/frisk/*'\n"):
            self.assertIn(line, self.lint)
        self.assertNotIn("continue-on-error", self.lint)
        self.assertNotIn("--fail-under", self.text)  # owner-held: set from the first CI run

    def test_dev_tools_come_only_from_the_extras(self) -> None:
        installs = re.findall(r"pip install (.+)", self.text)
        self.assertEqual(installs, ['-e ".[test]"', '-e ".[dev]"'])

    def test_contents_read_and_no_write_permission(self) -> None:
        self.assertRegex(self.text, r"(?m)^permissions:\n  contents: read\n")
        self.assertNotIn("write", self.text)

    def test_no_action_is_pinned_by_sha(self) -> None:
        refs = re.findall(r"uses: ([^\s@]+)@(\S+)", self.text)
        self.assertTrue(refs)
        for action, ref in refs:
            with self.subTest(action):
                self.assertNotRegex(ref, r"^[0-9a-f]{40}$")


class TestVerifyScript(unittest.TestCase):
    def test_named_interpreters_that_are_missing_are_skipped_and_fail(self) -> None:
        missing = ["/nonexistent/python3", "/nonexistent/python3.14"]
        env = {"PATH": "/usr/bin:/bin", "FRISK_VERIFY_PYTHONS": " ".join(missing)}
        r = subprocess.run(["bash", str(VERIFY)], env=env, capture_output=True, text=True, timeout=60, check=False)
        self.assertEqual(r.returncode, 1)
        self.assertEqual(r.stdout.splitlines(), [f"skip: {p} not found" for p in missing])
        self.assertIn("only 0 interpreter(s) ran", r.stderr)

    def test_it_installs_nothing(self) -> None:
        code = [line for line in VERIFY.read_text(encoding="utf-8").splitlines() if not line.lstrip().startswith("#")]
        for tool in ("pip", "uv", "curl", "wget", "venv"):
            self.assertNotRegex("\n".join(code), rf"\b{tool}\b")


if __name__ == "__main__":
    unittest.main()
