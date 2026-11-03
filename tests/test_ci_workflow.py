"""FR-E6 F3.08: CI runs the composite Action on the examples (job action-selftest).

Read from .github/workflows/ci.yml as text (no YAML library): the job has only
contents: read; the clean example must pass; the malicious one runs with
continue-on-error and a later step fails unless its outcome is 'failure' (passed through
env, never ${{ }} inside run:); both Action steps set sarif 'false', so nothing is
uploaded; and the malicious step's SARIF is checked structurally. That the job is green
on GitHub is checked after a push, not here.
Run: PYTHONPATH=src python3 -B -m unittest discover -s tests
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

from test_action import run_blocks

CI = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "ci.yml"


def job(text: str, name: str) -> str:
    """The lines of one job under jobs: (two-space indent), up to the next job."""
    match = re.search(rf"^  {re.escape(name)}:\n((?:(?:    .*)?\n)*)", text, re.MULTILINE)
    if match is None:
        raise AssertionError(f"no job {name}")
    return match.group(1)


def steps(body: str) -> list[str]:
    """Each step of a job, as its text."""
    return ["- " + part for part in re.split(r"^      - ", body, flags=re.MULTILINE)[1:]]


class TestActionSelftest(unittest.TestCase):
    def setUp(self) -> None:
        self.text = CI.read_text(encoding="utf-8")
        self.body = job(self.text, "action-selftest")
        self.steps = steps(self.body)

    def test_the_job_reads_contents_only(self) -> None:
        permissions = self.body.split("permissions:\n", 1)[1].split("    steps:", 1)[0]
        self.assertEqual(permissions.split(), ["contents:", "read"])
        self.assertIn("uses: actions/checkout@v4", self.steps[0])

    def test_both_action_steps_upload_nothing(self) -> None:
        local = [s for s in self.steps if "uses: ./\n" in s]
        self.assertEqual(len(local), 2)
        for step in local:
            self.assertIn("fail-on: block", step)
            self.assertIn('sarif: "false"', step)
        clean, malicious = local
        self.assertIn("targets: examples/clean-skill", clean)
        self.assertNotIn("continue-on-error", clean)
        self.assertIn("targets: examples/malicious-skill", malicious)
        self.assertIn("id: malicious", malicious)
        self.assertIn("continue-on-error: true", malicious)

    def test_a_step_asserts_the_malicious_outcome(self) -> None:
        (check,) = [s for s in self.steps if "steps.malicious.outcome" in s]
        self.assertIn("OUTCOME: ${{ steps.malicious.outcome }}", check)
        self.assertIn('run: test "$OUTCOME" = failure', check)
        self.assertGreater(self.steps.index(check), [i for i, s in enumerate(self.steps) if "id: malicious" in s][0])

    def test_a_step_checks_the_sarif_structurally(self) -> None:
        (check,) = [s for s in self.steps if "frisk.sarif" in s]
        for needle in ('"$RUNNER_TEMP/frisk.sarif"', 'doc["version"] == "2.1.0"',
                       'run["tool"]["driver"]["name"] == "frisk"', 'isinstance(run["results"], list)'):
            self.assertIn(needle, check)
        self.assertNotIn("upload-sarif", self.body)

    def test_no_expression_inside_any_run_block(self) -> None:
        for name, script in run_blocks(self.text).items():
            with self.subTest(step=name):
                self.assertNotIn("${{", script)


if __name__ == "__main__":
    unittest.main()
