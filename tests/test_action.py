"""FR-E6 H1.5: the composite Action runs no input as shell code, and scans once.

action.yml passes its inputs to the scripts through env only (no ${{ }} inside a run:
block), installs frisk into its own venv, and runs ONE scan that prints the text report and
writes SARIF with --sarif-out, keeping the --fail-on exit code. The Scan step's script is
run here in bash, as the runner runs it, with a targets value holding shell metacharacters
and a command that would create a file: each word is a literal path. The venv's python is a
symlink to this interpreter, so nothing this test writes is executed. No YAML library.
Run: PYTHONPATH=src python3 -B -m unittest discover -s tests
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from frisk.cli import main

REPO = Path(__file__).resolve().parent.parent
ACTION = REPO / "action.yml"


def run_blocks(text: str) -> dict[str, str]:
    """Each step's run: script, by step name (an unnamed step by its line number): the
    indented lines of a 'run: |' block, or a one-line 'run: ...' value."""
    blocks: dict[str, str] = {}
    lines = text.splitlines()
    name = ""
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("- name:"):
            name = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("- "):  # a step that is not named
            name = f"line {i + 1}"
        if stripped.startswith("- run:"):
            stripped = stripped[2:]
        if not stripped.startswith("run:"):
            continue
        value = stripped[len("run:"):].strip()
        if value not in ("|", ">"):
            blocks[name] = value
            continue
        indent = len(line) - len(line.lstrip())
        body = []
        for later in lines[i + 1:]:
            if later.strip() and len(later) - len(later.lstrip()) <= indent:
                break
            body.append(later)
        blocks[name] = "\n".join(body)
    return blocks


def run(argv: list[str]) -> tuple[int, str]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        code = main(argv)
    return code, out.getvalue()


class TestActionFile(unittest.TestCase):
    def setUp(self) -> None:
        self.text = ACTION.read_text(encoding="utf-8")
        self.blocks = run_blocks(self.text)

    def test_no_expression_inside_a_run_block(self) -> None:
        self.assertEqual(sorted(self.blocks), ["Install frisk", "Scan"])
        for name, script in self.blocks.items():
            with self.subTest(step=name):
                self.assertNotIn("${{", script)

    def test_inputs_reach_the_scan_through_env(self) -> None:
        for line in ("FRISK_TARGETS: ${{ inputs.targets }}", "FRISK_FAIL_ON: ${{ inputs.fail-on }}"):
            self.assertIn(line, self.text)
        self.assertIn('read -r -d \'\' -a targets <<< "$FRISK_TARGETS" || true', self.blocks["Scan"])

    def test_frisk_is_installed_into_a_venv_and_runs_once(self) -> None:
        self.assertIn('python3 -m venv "$RUNNER_TEMP/frisk-venv"', self.blocks["Install frisk"])
        self.assertNotIn("\npip ", "\n" + self.blocks["Install frisk"])
        scans = [s for s in self.blocks.values() if "frisk.cli" in s]
        self.assertEqual(len(scans), 1)
        self.assertIn('--sarif-out "$RUNNER_TEMP/frisk.sarif"', scans[0])

    def test_the_upload_is_gated_on_the_sarif_input(self) -> None:
        upload = self.text.split("- name: Upload SARIF", 1)[1]
        self.assertIn("if: ${{ inputs.sarif == 'true' && always() }}", upload)
        self.assertIn("sarif_file: ${{ runner.temp }}/frisk.sarif", upload)


class TestSarifOut(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.out = Path(tmp.name) / "f.sarif"
        self.addCleanup(os.chdir, os.getcwd())
        os.chdir(REPO)

    def test_one_scan_prints_the_text_report_and_writes_sarif(self) -> None:
        code, out = run(["examples", "--sarif-out", str(self.out)])
        self.assertEqual(code, 1)
        self.assertIn("verdict:   BLOCK", out)
        doc = json.loads(self.out.read_text(encoding="utf-8"))
        self.assertEqual(doc["version"], "2.1.0")
        self.assertEqual(doc["runs"][0]["tool"]["driver"]["name"], "frisk")
        self.assertTrue(doc["runs"][0]["results"])
        self.assertEqual(doc, json.loads(run(["examples", "--sarif"])[1]))

    def test_the_exit_code_follows_fail_on(self) -> None:
        for argv, code in ((["examples", "--fail-on", "never"], 0), (["examples", "--fail-on", "warn"], 1),
                           (["examples/clean-skill"], 0)):
            with self.subTest(argv=argv):
                self.assertEqual(run([*argv, "--sarif-out", str(self.out)])[0], code)
                self.assertEqual(json.loads(self.out.read_text(encoding="utf-8"))["version"], "2.1.0")

    def test_an_unwritable_sarif_file_exits_2(self) -> None:
        self.assertEqual(run(["examples/clean-skill", "--sarif-out", str(self.out.parent / "no" / "f.sarif")])[0], 2)


@unittest.skipUnless(shutil.which("bash"), "needs bash")
class TestScanStepInBash(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.runner_temp = Path(tmp.name)
        venv_bin = self.runner_temp / "frisk-venv" / "bin"
        venv_bin.mkdir(parents=True)
        (venv_bin / "python").symlink_to(sys.executable)
        self.script = run_blocks(ACTION.read_text(encoding="utf-8"))["Scan"]

    def step(self, targets: str, fail_on: str = "block") -> int:
        env = {**os.environ, "RUNNER_TEMP": str(self.runner_temp), "FRISK_TARGETS": targets,
               "FRISK_FAIL_ON": fail_on, "PYTHONPATH": str(REPO / "src")}
        # as a runner runs a bash step: bash --noprofile --norc -eo pipefail
        return subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", self.script], cwd=REPO,
                              env=env, capture_output=True, timeout=60, stdin=subprocess.DEVNULL).returncode

    def test_shell_metacharacters_in_targets_are_literal_paths(self) -> None:
        marker = self.runner_temp / "created"
        for targets in (f"x;touch {marker}", f"$(touch {marker})", f"`touch {marker}`", f"x&&touch {marker}",
                        f"x|touch {marker}", f"examples/clean-skill;touch${{IFS}}{marker}"):
            with self.subTest(targets=targets):
                self.assertEqual(self.step(targets), 2)
                self.assertFalse(marker.exists())

    def test_a_target_that_looks_like_an_option_is_a_path(self) -> None:
        self.assertEqual(self.step("--fail-on never examples/malicious-skill"), 2)  # '--fail-on' is no path

    def test_every_line_of_a_multi_line_targets_value_is_scanned(self) -> None:
        self.assertEqual(self.step("examples/clean-skill\nexamples/malicious-skill\n"), 1)
        self.assertEqual(self.step("examples/clean-skill\n\n  examples/clean-skill\n"), 0)

    def test_the_step_scans_and_writes_sarif(self) -> None:
        sarif = self.runner_temp / "frisk.sarif"
        self.assertEqual(self.step("examples/clean-skill examples/malicious-skill", "never"), 0)
        self.assertEqual(self.step("examples/clean-skill"), 0)
        self.assertEqual(json.loads(sarif.read_text(encoding="utf-8"))["version"], "2.1.0")
        self.assertEqual(self.step("examples/malicious-skill"), 1)


if __name__ == "__main__":
    unittest.main()
