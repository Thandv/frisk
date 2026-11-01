"""MCP servers are classified the way they really launch (F1.09).

Every path lives in a temp dir with HOME patched to a directory inside it. Assertions carry
a label only (longMessage is off), so a failure never prints an arg or env value. Nothing
is executed and nothing touches the network.
Run: PYTHONPATH=src python3 -B -m unittest discover -s tests
"""
from __future__ import annotations

import contextlib
import os
import tempfile
import unittest
from collections.abc import Iterator
from pathlib import Path
from unittest import mock

from frisk.sources import _classify

RELATIVE = "relative path and no absolute 'cwd' in the config: cannot tell which file runs"
UNRESOLVED = "could not resolve a local source to scan"


@contextlib.contextmanager
def chdir(path: Path) -> Iterator[None]:
    here = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(here)


class ClassifyCase(unittest.TestCase):
    longMessage = False  # a failure shows the label, never the compared values

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.home = self.tmp / "home"
        self.home.mkdir()
        home = mock.patch.dict(os.environ, {"HOME": str(self.home)})
        home.start()
        self.addCleanup(home.stop)
        self.proj = self.make("home/proj/server.py", 'print("hello")\n').parent
        self.data = self.tmp / "data"
        self.data.mkdir()

    def make(self, rel: str, text: str = "") -> Path:
        path = self.tmp / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def check(self, label: str, spec: dict, kind: str, root: Path | None = None, detail: str | None = None) -> None:
        s = _classify("s", spec)
        self.assertEqual(s.kind, kind, label + ": kind")
        self.assertEqual(s.scannable, kind == "local", label + ": scannable")
        if root is not None:
            self.assertEqual(Path(s.ref), root, label + ": root")
        if detail is not None:
            self.assertEqual(s.detail, detail, label + ": detail")


class UvTest(ClassifyCase):
    def test_directory_or_project_is_the_root(self) -> None:
        p = str(self.proj)
        for label, args in (
            ("global --directory", ["--directory", p, "run", "server.py"]),
            ("--directory=", ["--directory=" + p, "run", "server.py"]),
            ("run --directory", ["run", "--directory", p, "server.py"]),
            ("global --project", ["--project", p, "run", "mcp-entry"]),
            ("run --project=", ["run", "--project=" + p, "--with", "mcp", "mcp-entry"]),
        ):
            with self.subTest(label):
                self.check(label, {"command": "uv", "args": args}, "local", self.proj, "local source via uv")

    def test_absolute_uv_command_is_recognised(self) -> None:
        self.check("abs uv", {"command": "/opt/tools/bin/uv", "args": ["--directory", str(self.proj), "run", "x"]},
                   "local", self.proj)

    def test_relative_directory_resolves_against_cwd_only(self) -> None:
        spec = {"command": "uv", "args": ["--directory", "proj", "run", "server.py"]}
        self.check("no cwd", spec, "unknown", detail=RELATIVE)
        self.check("cwd", {**spec, "cwd": str(self.home)}, "local", self.proj)

    def test_missing_directory_is_unknown(self) -> None:
        self.check("missing", {"command": "uv", "args": ["--directory", str(self.tmp / "gone"), "run", "x"]},
                   "unknown", detail=UNRESOLVED)

    def test_script_without_directory_uses_cwd(self) -> None:
        (self.proj / "pyproject.toml").write_text("", encoding="utf-8")
        self.check("script in cwd", {"command": "uv", "args": ["run", "server.py"], "cwd": str(self.proj)},
                   "local", self.proj)
        self.check("entry point, cwd is the root",
                   {"command": "uv", "args": ["run", "mcp-entry"], "cwd": str(self.proj)}, "local", self.proj)
        self.check("relative script, no cwd", {"command": "uv", "args": ["run", "server.py"]},
                   "unknown", detail=RELATIVE)
        self.check("absolute script, no cwd", {"command": "uv", "args": ["run", str(self.proj / "server.py")]},
                   "local", self.proj)

    def test_options_after_the_script_belong_to_the_script(self) -> None:
        args = ["run", "server.py", "--directory", str(self.data)]
        self.check("trailing option", {"command": "uv", "args": args, "cwd": str(self.proj)}, "local", self.proj)

    def test_uv_tool_run_is_a_package(self) -> None:
        for label, args, pkg in (("tool run", ["tool", "run", "acme-mcp"], "acme-mcp"),
                                 ("tool run --from", ["tool", "run", "--from", "acme-mcp", "acme"], "acme-mcp")):
            with self.subTest(label):
                s = _classify("s", {"command": "uv", "args": args})
                self.assertEqual((s.kind, s.ref, s.scannable), ("package", pkg, False), label)

    def test_other_uv_subcommands_are_unknown(self) -> None:
        self.check("no run", {"command": "uv", "args": ["--version"]}, "unknown", detail=UNRESOLVED)


class CwdTest(ClassifyCase):
    def test_relative_script_resolves_against_cwd_not_a_later_path(self) -> None:
        self.make("home/app/index.js", "console.log(1)\n")
        (self.home / "app" / "package.json").write_text("{}", encoding="utf-8")
        spec = {"command": "node", "args": ["index.js", str(self.data)]}
        self.check("cwd", {**spec, "cwd": str(self.home / "app")}, "local", self.home / "app")
        self.check("no cwd", spec, "unknown", detail=RELATIVE)

    def test_frisks_own_working_directory_is_never_used(self) -> None:
        self.make("here/index.js", "console.log(1)\n")
        with chdir(self.tmp / "here"), mock.patch("os.getcwd", side_effect=AssertionError("getcwd")):
            self.check("relative script", {"command": "node", "args": ["index.js"]}, "unknown", detail=RELATIVE)
            self.check("relative command", {"command": "./index.js"}, "unknown", detail=RELATIVE)

    def test_relative_cwd_is_unusable(self) -> None:
        self.check("relative cwd", {"command": "node", "args": ["index.js"], "cwd": "app"}, "unknown", detail=RELATIVE)

    def test_cwd_and_args_expand_tilde_against_home(self) -> None:
        self.check("~ cwd", {"command": "python3", "args": ["server.py"], "cwd": "~/proj"}, "local", self.proj)
        self.check("~ arg", {"command": "python3", "args": ["~/proj/server.py"]}, "local", self.proj)

    def test_relative_command_path_resolves_against_cwd(self) -> None:
        exe = self.make("home/proj/bin/server", "#!/bin/sh\n")
        self.check("cwd", {"command": "./bin/server", "cwd": str(self.proj)}, "local", exe)
        self.check("no cwd", {"command": "bin/server"}, "unknown", detail=RELATIVE)


class ScriptPreferenceTest(ClassifyCase):
    def test_script_beats_an_earlier_existing_path(self) -> None:
        spec = {"command": "python3", "args": [str(self.data), str(self.proj / "server.py")]}
        self.check("script after data", spec, "local", self.proj)

    def test_shebang_marks_a_script_without_extension(self) -> None:
        tool = self.make("home/tool/run", "#!/bin/sh\necho hi\n")
        self.check("shebang", {"command": "bash", "args": [str(self.data), str(tool)]}, "local", tool.parent)

    def test_without_a_script_the_first_existing_path_counts(self) -> None:
        notes = self.make("home/docs/notes.txt", "plain\n")
        self.check("file", {"command": "bash", "args": [str(notes)]}, "local", notes.parent)
        self.check("directory", {"command": "node", "args": [str(self.data)]}, "local", self.data)

    def test_the_first_script_like_arg_decides(self) -> None:
        other = str(self.proj / "server.py")
        self.check("missing script", {"command": "node", "args": [str(self.tmp / "gone.js"), str(self.data)]},
                   "unknown", detail=UNRESOLVED)
        self.check("relative first", {"command": "node", "args": ["main.js", other]}, "unknown", detail=RELATIVE)
        self.check("absolute first", {"command": "node", "args": [other, "main.js"]}, "local", self.proj)

    def test_a_directory_named_like_a_script_is_not_a_script(self) -> None:
        (self.tmp / "home" / "pkg.py").mkdir()
        self.check("dir.py", {"command": "python3", "args": [str(self.tmp / "home" / "pkg.py")]},
                   "unknown", detail=UNRESOLVED)


class WalkUpTest(ClassifyCase):
    def deep_script(self) -> Path:
        return self.make("home/l4/l3/l2/l1/l0/server.py", "x = 1\n")

    def test_marker_three_levels_up_is_found(self) -> None:
        script = self.deep_script()
        for marker in ("pyproject.toml", "package.json", ".git/", ".git"):
            with self.subTest(marker):
                where = self.home / "l4" / "l3" / marker.rstrip("/")
                if marker.endswith("/"):
                    where.mkdir()
                else:
                    where.write_text("", encoding="utf-8")
                self.check(marker, {"command": "python3", "args": [str(script)]}, "local", self.home / "l4" / "l3")
                if where.is_dir():
                    where.rmdir()
                else:
                    where.unlink()

    def test_marker_four_levels_up_is_not_reached(self) -> None:
        script = self.deep_script()
        (self.home / "l4" / "pyproject.toml").write_text("", encoding="utf-8")
        self.check("4 levels", {"command": "python3", "args": [str(script)]}, "local", script.parent)

    def test_nearest_marker_wins(self) -> None:
        script = self.deep_script()
        (self.home / "l4" / "l3" / "pyproject.toml").write_text("", encoding="utf-8")
        level1 = script.parent.parent
        (level1 / "package.json").write_text("{}", encoding="utf-8")
        self.check("nearest", {"command": "python3", "args": [str(script)]}, "local", level1)

    def test_the_walk_never_looks_at_home(self) -> None:
        (self.home / ".git").mkdir()
        script = self.make("home/a/b/server.py", "x = 1\n")
        self.check("marker in HOME", {"command": "python3", "args": [str(script)]}, "local", script.parent)

    def test_the_walk_never_goes_above_home(self) -> None:
        (self.tmp / "package.json").write_text("{}", encoding="utf-8")
        script = self.make("home/a/server.py", "x = 1\n")
        self.check("marker above HOME", {"command": "python3", "args": [str(script)]}, "local", script.parent)

    def test_a_script_directly_in_home_is_scanned_alone(self) -> None:
        script = self.make("home/server.py", "x = 1\n")
        self.check("script in HOME", {"command": "python3", "args": [str(script)]}, "local", script)

    def test_home_or_above_is_never_a_root(self) -> None:
        for label, arg in (("HOME", str(self.home)), ("~", "~"), ("above HOME", str(self.tmp))):
            with self.subTest(label):
                self.check(label, {"command": "bash", "args": [arg]}, "unknown")


class InterpreterTest(ClassifyCase):
    def test_a_local_executable_is_the_source_not_its_data_args(self) -> None:
        exe = self.make("home/srv/bin/server", "#!/bin/sh\n")
        self.check("exe", {"command": str(exe), "args": ["--db", str(self.data)]}, "local", exe)

    def test_a_bare_non_interpreter_command_ignores_path_args(self) -> None:
        self.check("bare", {"command": "acme-git-mcp", "args": ["--repository", str(self.data)]},
                   "unknown", detail=UNRESOLVED)

    def test_versioned_interpreter_names_count(self) -> None:
        for cmd in ("python3.12", "/opt/x/bin/python3", "node22"):
            with self.subTest(cmd):
                self.check(cmd, {"command": cmd, "args": [str(self.proj / "server.py")]}, "local", self.proj)


if __name__ == "__main__":
    unittest.main()
