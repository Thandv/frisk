"""FR-E7 t7 (F4.04): the release tag check and the publish workflow, which no test runs.

scripts/check_tag_version.py is run as a child process: 'v' + __version__ passes; another
version, an empty tag, a tag without the 'v', no tag, and a tree whose __init__.py states no
version fail with exit 1 and one stderr line. .github/workflows/publish.yml is read as text:
the publish job needs the build job, which needs the test job and runs the tag check and
twine check; the upload uses environment pypi with attestations; write permissions are
scoped to the one job that needs each; no action is pinned by SHA.
Run: PYTHONPATH=src python3 -B -m unittest discover -s tests
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from _subproc import REPO
from frisk import __version__
from test_ci_workflow import job

SCRIPT = REPO / "scripts" / "check_tag_version.py"
PUBLISH = REPO / ".github" / "workflows" / "publish.yml"


def check(*args: str, script: Path = SCRIPT) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, "-B", str(script), *args], capture_output=True, text=True, timeout=30,
                          check=False)


class TestCheckTagVersion(unittest.TestCase):
    def test_the_matching_tag_passes(self) -> None:
        r = check(f"v{__version__}")
        self.assertEqual((r.returncode, r.stderr), (0, ""))

    def test_other_tags_fail_with_one_line(self) -> None:
        for tag in ("v9.9.9", f"v{__version__}.1", "", __version__, f"V{__version__}", f"v{__version__} "):
            with self.subTest(tag=tag):
                r = check(tag)
                self.assertEqual((r.returncode, r.stdout), (1, ""))
                self.assertEqual(len(r.stderr.splitlines()), 1, r.stderr)
                self.assertIn(f"expected v{__version__}", r.stderr)

    def test_no_tag_or_two_tags_fail(self) -> None:
        for args in ((), ("v1", "v2")):
            with self.subTest(args=args):
                r = check(*args)
                self.assertEqual(r.returncode, 1)
                self.assertIn("usage:", r.stderr)

    def test_an_init_without_a_version_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "scripts").mkdir()
            (Path(tmp) / "src" / "frisk").mkdir(parents=True)
            copy = Path(tmp) / "scripts" / SCRIPT.name
            shutil.copy(SCRIPT, copy)
            (Path(tmp) / "src" / "frisk" / "__init__.py").write_text('"""no version here"""\n', encoding="utf-8")
            r = check(f"v{__version__}", script=copy)
            self.assertEqual(r.returncode, 1)
            self.assertIn("no __version__", r.stderr)


class TestPublishWorkflow(unittest.TestCase):
    def setUp(self) -> None:
        self.text = PUBLISH.read_text(encoding="utf-8")
        self.jobs = {name: job(self.text, name) for name in ("test", "build", "publish", "release-assets")}

    def test_it_runs_only_on_a_published_release(self) -> None:
        self.assertIn("on:\n  release:\n    types: [published]\n", self.text)

    def test_publishing_is_gated_on_the_tests_and_the_tag_check(self) -> None:
        self.assertIn("bash scripts/verify.sh", self.jobs["test"])
        build = self.jobs["build"]
        self.assertIn("    needs: test\n", build)
        order = ['python scripts/check_tag_version.py "$GITHUB_REF_NAME"', "python -m build",
                 "python -m twine check --strict dist/*", "actions/upload-artifact@v4"]
        self.assertEqual([build.index(s) for s in order], sorted(build.index(s) for s in order))
        self.assertIn("    needs: build\n", self.jobs["publish"])
        self.assertIn("    needs: build\n", self.jobs["release-assets"])

    def test_the_upload_uses_the_pypi_environment_with_attestations(self) -> None:
        publish = self.jobs["publish"]
        self.assertIn("    environment: pypi\n", publish)
        self.assertIn("uses: pypa/gh-action-pypi-publish@release/v1", publish)
        self.assertIn("          attestations: true\n", publish)

    def test_dist_is_attached_to_the_release(self) -> None:
        self.assertIn('gh release upload "$TAG" dist/*', self.jobs["release-assets"])

    def test_permissions_are_scoped_per_job(self) -> None:
        self.assertRegex(self.text, r"(?m)^permissions:\n  contents: read\n\njobs:")
        writes = {name for name, body in self.jobs.items() if "write" in body}
        self.assertEqual(writes, {"publish", "release-assets"})
        self.assertIn("      id-token: write", self.jobs["publish"])
        self.assertNotIn("contents: write", self.jobs["publish"])
        self.assertIn("      contents: write", self.jobs["release-assets"])
        self.assertNotIn("id-token", self.jobs["release-assets"])

    def test_no_expression_inside_a_run_line_and_no_sha_pin(self) -> None:
        for line in self.text.splitlines():
            if line.strip().startswith("run:"):
                self.assertNotIn("${{", line)
        for action, ref in re.findall(r"uses: ([^\s@]+)@(\S+)", self.text):
            self.assertNotRegex(ref, r"^[0-9a-f]{40}$", action)


if __name__ == "__main__":
    unittest.main()
