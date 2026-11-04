"""FR-E8 t2 (F4.05): every `frisk ...` line in README.md's bash fences runs, with the exit code it states.

Each such line ends with an `[exit N]` annotation in its comment. A fence right after a
`<!-- doc-test: network -->` line needs the network (a git URL) and is not run. A fence's
lines run in order in one sandbox from scripts/gen_readme_demo.py (temp working directory
holding a copy of examples/ and the fixture MCP config, temp HOME holding that config at
~/.claude.json and Claude Desktop's path), through its run_frisk(): no shell. A line is
split with shlex; a leading `~` means the sandbox HOME, and only a trailing `< FILE` (stdin
from the sandbox) and `> FILE` (stdout into the sandbox) are understood: any other shell
syntax fails the test. Nothing is written into the repo and nothing touches the network.
Run: PYTHONPATH=src python3 -B -m unittest discover -s tests
"""
from __future__ import annotations

import re
import shlex
import unittest
from pathlib import Path

from _scripts import load_script

gen = load_script("gen_readme_demo")
FENCE = re.compile(r"^```(\w*)\n(.*?)^```$", re.DOTALL | re.MULTILINE)
SHELL_FENCES = {"bash", "sh", "shell"}
NETWORK = "<!-- doc-test: network -->"
EXIT = re.compile(r"\[exit (\d+)\]\s*$")
OPERATORS = set("();<>|&")


class Command:
    def __init__(self, line: str, home: Path) -> None:
        """Parse one README line; ValueError when it has no annotation or unsupported shell syntax."""
        m = EXIT.search(line)
        if m is None:
            raise ValueError(f"no [exit N] annotation: {line}")
        self.exit = int(m.group(1))
        lexer = shlex.shlex(line[:m.start()], posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        tokens = list(lexer)
        self.stdin: str | None = None
        self.stdout: str | None = None
        while len(tokens) >= 2 and tokens[-2] in ("<", ">") and not set(tokens[-1]) <= OPERATORS:
            op, target = tokens[-2], tokens[-1]
            if (self.stdin if op == "<" else self.stdout) is not None:
                raise ValueError(f"two {op} redirects: {line}")
            if op == "<":
                self.stdin = target
            else:
                self.stdout = target
            del tokens[-2:]
        bad = [t for t in tokens if set(t) <= OPERATORS or any(c in t for c in "$`*")]
        if tokens[:1] != ["frisk"] or bad:
            raise ValueError(f"unsupported shell syntax {bad}: {line}")
        self.args = [str(home) + t[1:] if t == "~" or t.startswith("~/") else t for t in tokens[1:]]


def shell_fences(readme: str) -> list[tuple[bool, list[str]]]:
    """(needs the network, its `frisk` lines) for each bash fence."""
    out = []
    for m in FENCE.finditer(readme):
        lines = [ln.strip() for ln in m.group(2).splitlines() if ln.strip().startswith("frisk ")]
        if m.group(1) not in SHELL_FENCES:
            if lines:
                raise ValueError(f"frisk commands in a ```{m.group(1)} fence: {lines}")
            continue
        before = readme[:m.start()].rstrip("\n").rsplit("\n", 1)[-1]
        out.append((before == NETWORK, lines))
    return out


def run_fence(lines: list[str]) -> list[tuple[str, int, int, str]]:
    """Run a fence's lines in order in one sandbox: (line, expected exit, real exit, stderr)."""
    results = []
    with gen.sandbox() as box:
        for line in lines:
            cmd = Command(line, box.home)
            stdin = (box.cwd / cmd.stdin).read_bytes() if cmd.stdin else b""
            r = gen.run_frisk(cmd.args, box, stdin=stdin)
            if cmd.stdout:
                (box.cwd / cmd.stdout).write_bytes(r.stdout)
            results.append((line, cmd.exit, r.returncode, r.stderr.decode("utf-8", "replace")))
    return results


class TestReadmeCommands(unittest.TestCase):
    def setUp(self) -> None:
        self.fences = shell_fences(gen.README.read_text(encoding="utf-8"))

    def test_every_frisk_line_exits_as_annotated(self) -> None:
        ran = 0
        for network, lines in self.fences:
            if network:
                continue
            for line, expected, real, err in run_fence(lines):
                ran += 1
                with self.subTest(line=line):
                    self.assertEqual(real, expected, err)
        self.assertGreaterEqual(ran, 10)

    def test_only_git_url_scans_are_skipped(self) -> None:
        skipped = [line for network, lines in self.fences if network for line in lines]
        self.assertEqual(skipped, ["frisk https://github.com/owner/repo    # shallow-clone a repo and scan it"])

    def test_a_wrong_or_missing_annotation_fails(self) -> None:
        line = "frisk examples/malicious-skill   # [exit 0]"
        self.assertEqual([(e, r) for _, e, r, _ in run_fence([line])], [(0, 1)])
        with self.assertRaisesRegex(ValueError, "no \\[exit N\\]"):
            run_fence(["frisk examples/clean-skill   # scan it"])

    def test_redirects_are_parsed_never_run_by_a_shell(self) -> None:
        home = Path("/h")
        cmd = Command("frisk --stdin < in.md > out.json   # [exit 0]", home)
        self.assertEqual((cmd.args, cmd.stdin, cmd.stdout), (["--stdin"], "in.md", "out.json"))
        self.assertEqual(Command("frisk ~/.claude.json # [exit 0]", home).args, ["/h/.claude.json"])
        for line in ("frisk x | sh # [exit 0]", "frisk x; rm y # [exit 0]", "frisk $(x) # [exit 0]",
                     "frisk x && y # [exit 0]", "frisk x > a > b # [exit 0]", "frisk * # [exit 0]",
                     "frisk `x` # [exit 0]", "python3 -m frisk # [exit 0]"):
            with self.subTest(line=line), self.assertRaises(ValueError):
                Command(line, home)

    def test_a_frisk_line_outside_a_shell_fence_fails(self) -> None:
        with self.assertRaises(ValueError):
            shell_fences("```text\nfrisk examples # [exit 0]\n```\n")


if __name__ == "__main__":
    unittest.main()
