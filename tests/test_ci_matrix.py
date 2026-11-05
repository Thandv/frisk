"""FR-E7 t5 (F4.02): the CI matrix and gates, read from .github/workflows/ci.yml as text.

Python 3.9 to 3.14 on ubuntu-latest plus one macos-latest job, each running scripts/verify.sh
and pytest; a blocking lint job with ruff, mypy on src and a coverage report (no floor yet:
the owner sets it from the first CI number); contents: read; action refs are tags, never
SHAs. That the run is green is checked on GitHub after the owner pushes, not here. Also
scripts/verify.sh, run as a copy in an empty tree so it never runs the suite: its
FRISK_VERIFY_PYTHONS override on missing paths, and its lint step with fake ruff, mypy and
interpreter (a linter found on PATH or as `python -m`, failing when found neither way or
when it fails, skipped only by FRISK_VERIFY_LINT=skip, which the CI test legs set).
Run: PYTHONPATH=src python3 -B -m unittest discover -s tests
"""
from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

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
                            'FRISK_MIN_PYTHONS: "1"' in s and "FRISK_VERIFY_LINT: skip" in s for s in runs))
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


# A fake interpreter for verify.sh: it answers the realpath and version probes, passes the
# unittest run, cannot import pytest or ruff, and imports and runs mypy (logging its argv).
FAKE_PYTHON = """#!/bin/sh
case "$*" in
  *realpath*) echo "$0" ;;
  *platform*) echo 3.99.0 ;;
  *"-m unittest"*) echo "Ran 0 tests in 0.0s" >&2 ;;
  "-c import mypy") ;;
  "-m mypy src") echo "python $*" >> "$(dirname "$0")/calls" ;;
  *) exit 1 ;;
esac
"""


def fake_tool(bin_dir: Path, name: str, status: int) -> None:
    """An executable `name` in bin_dir that logs its argv to bin_dir/calls and exits `status`."""
    path = bin_dir / name
    path.write_text(f'#!/bin/sh\necho "{name} $*" >> "$(dirname "$0")/calls"\nexit {status}\n', encoding="utf-8")
    path.chmod(0o755)


def run_verify(env: dict[str, str]) -> tuple[subprocess.CompletedProcess[str], str]:
    """Run a copy of verify.sh in an empty tree (there is no suite in it, so this test can never
    run the suite again): its result, and the calls the fakes logged in <tree>/bin."""
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / "scripts").mkdir()
        (Path(tmp) / "bin").mkdir()
        copy = Path(tmp) / "scripts" / "verify.sh"
        shutil.copy(VERIFY, copy)
        full = {key: value.replace("{tmp}", tmp) for key, value in env.items()}
        for name, status in (("ruff", 0), ("mypy", 0), ("ruff-fails", 1), ("mypy-fails", 1)):
            fake_tool(Path(tmp) / "bin", name, status)
        python = Path(tmp) / "bin" / "python3"
        python.write_text(FAKE_PYTHON, encoding="utf-8")
        python.chmod(0o755)
        for name in env.get("FAILING", "").split():  # a linter that fails replaces the passing one
            shutil.move(str(Path(tmp) / "bin" / f"{name}-fails"), str(Path(tmp) / "bin" / name))
        r = subprocess.run(["bash", str(copy)], env=full, stdin=subprocess.DEVNULL, capture_output=True,
                           text=True, timeout=60, check=False)
        calls = Path(tmp) / "bin" / "calls"
        return r, calls.read_text(encoding="utf-8").replace(tmp, "{tmp}") if calls.exists() else ""


class TestVerifyScript(unittest.TestCase):
    # No interpreter runs (FRISK_MIN_PYTHONS=0): only the lint step does.
    NO_PYTHON = {"FRISK_VERIFY_PYTHONS": "/nonexistent/python3", "FRISK_MIN_PYTHONS": "0"}
    # bin/ holds ruff, mypy and the fake interpreter; /usr/bin:/bin hold neither linter.
    WITH_TOOLS = {"PATH": "{tmp}/bin:/usr/bin:/bin", **NO_PYTHON}
    WITHOUT_TOOLS = {"PATH": "/usr/bin:/bin", **NO_PYTHON}

    def test_named_interpreters_that_are_missing_are_skipped_and_fail(self) -> None:
        missing = ["/nonexistent/python3", "/nonexistent/python3.14"]
        r, _ = run_verify({"PATH": "/usr/bin:/bin", "FRISK_VERIFY_PYTHONS": " ".join(missing)})
        self.assertEqual(r.returncode, 1)
        self.assertEqual(r.stdout.splitlines(), [f"skip: {p} not found" for p in missing])
        self.assertIn("only 0 interpreter(s) ran", r.stderr)

    def test_linters_on_path_run_as_ci_runs_them(self) -> None:
        r, calls = run_verify(self.WITH_TOOLS)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(calls.splitlines(), ["ruff check", "mypy src"])
        self.assertIn("PASS  ruff check  (ruff)\nPASS  mypy src  (mypy)\n", r.stdout)

    def test_a_missing_linter_fails_and_is_never_skipped(self) -> None:
        r, _ = run_verify(self.WITHOUT_TOOLS)
        self.assertEqual(r.returncode, 1)
        self.assertIn("FAIL  ruff check  (ruff not on PATH and not importable", r.stdout)
        self.assertIn("FAIL  mypy src  (mypy not on PATH and not importable", r.stdout)
        self.assertNotIn("skipped", r.stdout)
        self.assertIn("verify: 2 linter(s) failed", r.stderr)

    def test_a_failing_linter_fails(self) -> None:
        for name in ("ruff", "mypy"):
            with self.subTest(name):
                r, _ = run_verify({**self.WITH_TOOLS, "FAILING": name})
                self.assertEqual(r.returncode, 1)
                self.assertIn(f"FAIL  {name} ", r.stdout)
                self.assertIn("verify: 1 linter(s) failed", r.stderr)

    def test_mypy_runs_as_a_module_of_an_interpreter_that_ran(self) -> None:
        env = {"PATH": "/usr/bin:/bin", "FRISK_VERIFY_PYTHONS": "{tmp}/bin/python3", "FRISK_MIN_PYTHONS": "1"}
        r, calls = run_verify(env)
        self.assertEqual(calls.splitlines(), ["python -m mypy src"])
        self.assertRegex(r.stdout, r"PASS  3\.99\.0 +\S+/bin/python3  unittest")
        self.assertRegex(r.stdout, r"PASS  mypy src  \(\S+/bin/python3 -m mypy\)")
        self.assertIn("FAIL  ruff check  (ruff not on PATH", r.stdout)  # the fake cannot import ruff
        self.assertEqual(r.returncode, 1)

    def test_skip_is_explicit_and_skips_both(self) -> None:
        r, calls = run_verify({**self.WITHOUT_TOOLS, "FRISK_VERIFY_LINT": "skip"})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("skipped: ruff check and mypy src (FRISK_VERIFY_LINT=skip)\n", r.stdout)
        self.assertEqual(calls, "")

    def test_an_unknown_lint_mode_is_a_usage_error(self) -> None:
        r, _ = run_verify({**self.WITH_TOOLS, "FRISK_VERIFY_LINT": "off"})
        self.assertEqual(r.returncode, 2)
        self.assertIn("FRISK_VERIFY_LINT must be 'require' or 'skip', got 'off'", r.stderr)

    def test_it_installs_nothing(self) -> None:
        code = [line for line in VERIFY.read_text(encoding="utf-8").splitlines() if not line.lstrip().startswith("#")]
        for tool in ("pip", "uv", "curl", "wget", "venv"):
            self.assertNotRegex("\n".join(code), rf"\b{tool}\b")


if __name__ == "__main__":
    unittest.main()
