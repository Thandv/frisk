"""docs/WALKTHROUGH.md's pasted commands are re-run, and the pasted output must match what they print.

Each ```console fence is a list of commands: a `$ ` line starts one, `> ` lines continue it
(a here-document), and every other line is the output pasted under it. A fence right after a
`<!-- doc-test: network -->` line needs the network or changes the machine (a clone, a
virtual environment, pip) and is not run; it may not hold a `frisk` command, so the marker
cannot hide a check. Every other fence runs, in order, in one `sh` in a sandbox: a temp
working directory holding a copy of examples/, a temp HOME, no network, and a `frisk`
that is `python -m frisk.cli` from this checkout. Each command's output (stdout and stderr
together) is compared with the pasted text after the temp directories, and timings
are normalised (the version number is not: a stale one fails). A command whose marker is
missing from the shell's output (the shell died first) fails too. A `frisk` command with no pasted output, or an unmarked
fence with no command at all, fails: that block would check nothing.
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
from unittest import mock

from _home import CACHE_VARS
from _subproc import REPO, child_env

WALKTHROUGH = REPO / "docs" / "WALKTHROUGH.md"
NETWORK = "<!-- doc-test: network -->"
FENCE = re.compile(r"^```console\n(.*?)^```$", re.DOTALL | re.MULTILINE)
MARK = "@@walkthrough-command {}@@"
TIME = re.compile(r"\b\d+(?:\.\d+)?\s?(?:ms|s)\b")


class Command:
    def __init__(self, shell: list[str]) -> None:
        self.shell = shell  # the lines to run, without the `$ ` and `> ` prefixes
        self.output: list[str] = []

    @property
    def is_frisk(self) -> bool:
        return self.shell[0].split()[:1] == ["frisk"]


class Fence:
    def __init__(self, commands: list[Command], network: bool) -> None:
        self.commands = commands
        self.network = network


def parse(text: str) -> list[Fence]:
    """The console fences of `text`, each with its commands and their pasted output."""
    fences = []
    for m in FENCE.finditer(text):
        before = text[:m.start()].rstrip("\n").rsplit("\n", 1)[-1]
        commands: list[Command] = []
        for line in m.group(1).splitlines():
            if line.startswith("$ "):
                commands.append(Command([line[2:]]))
            elif line.startswith("> ") and commands and not commands[-1].output:
                commands[-1].shell.append(line[2:])
            elif commands:
                commands[-1].output.append(line)
            else:
                raise ValueError(f"output before any command: {line!r}")
        fences.append(Fence(commands, before.strip() == NETWORK))
    return fences


def normalise(text: str, roots: list[Path]) -> str:
    """Temp directories and timings replaced; trailing space dropped. The version is not, so a
    walkthrough that names an old version fails here."""
    for root in sorted({str(r) for r in roots} | {str(r.resolve()) for r in roots}, key=len, reverse=True):
        text = text.replace(root, "<tmp>")
    text = TIME.sub("<time>", text)
    return "\n".join(line.rstrip() for line in text.strip("\n").splitlines())


def problems(fences: list[Fence]) -> list[str]:
    """Why the walkthrough would check nothing, apart from any output that differs."""
    found = []
    for n, fence in enumerate(fences, 1):
        if not fence.commands:
            found.append(f"fence {n} has no command")
        for cmd in fence.commands:
            if fence.network and cmd.is_frisk:
                found.append(f"fence {n} is marked network but runs `{cmd.shell[0]}`")
            if not fence.network and cmd.is_frisk and not any(line.strip() for line in cmd.output):
                found.append(f"fence {n}: `{cmd.shell[0]}` has no pasted output to compare")
    return found


def run_walkthrough(fences: list[Fence], tmp: Path) -> tuple[list[Command], dict[int, str]]:
    """Run the unmarked fences' commands in one shell; (the commands, output by command index)."""
    home, work, bin_dir = tmp / "home", tmp / "work", tmp / "bin"
    for d in (home, work, bin_dir):
        d.mkdir()
    shutil.copytree(REPO / "examples", work / "examples")
    frisk = bin_dir / "frisk"
    frisk.write_text(f'#!/bin/sh\nexec "{sys.executable}" -B -m frisk.cli "$@"\n', encoding="utf-8")
    frisk.chmod(0o755)
    commands = [c for f in fences if not f.network for c in f.commands]
    script = []
    for i, cmd in enumerate(commands):
        script.append(f"echo '{MARK.format(i)}'")
        script.append("{\n" + "\n".join(cmd.shell) + "\n} 2>&1")
    env = child_env(str(home), PYTHONUNBUFFERED="1", PYTHONDONTWRITEBYTECODE="1")
    env["PATH"] = f"{bin_dir}:{env['PATH']}"
    for var in CACHE_VARS:
        env.pop(var, None)
    done = subprocess.run(["sh", "-c", "\n".join(script)], cwd=str(work), env=env, stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=300, check=False)
    pieces: dict[int, str] = {}
    current = None
    for line in done.stdout.decode("utf-8").splitlines():
        m = re.fullmatch(r"@@walkthrough-command (\d+)@@", line)
        if m:
            current = int(m.group(1))
            pieces[current] = ""
        elif current is not None:
            pieces[current] += line + "\n"
    return commands, pieces


def differences(fences: list[Fence], tmp: Path) -> list[str]:
    commands, pieces = run_walkthrough(fences, tmp)
    roots = [tmp]
    diffs = []
    for i, cmd in enumerate(commands):
        if i not in pieces:  # the shell died before this command, or it printed no marker
            diffs.append(f"`{cmd.shell[0]}`\n--- did not run")
            continue
        want = normalise("\n".join(cmd.output), roots)
        got = normalise(pieces[i], roots)
        if want != got:
            diffs.append(f"`{cmd.shell[0]}`\n--- pasted\n{want}\n--- now\n{got}")
    return diffs


class TestWalkthroughDrift(unittest.TestCase):
    def setUp(self) -> None:
        self.text = WALKTHROUGH.read_text(encoding="utf-8")
        self.fences = parse(self.text)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)

    def test_the_walkthrough_has_no_block_that_checks_nothing(self) -> None:
        self.assertEqual(problems(self.fences), [])
        run = [c for f in self.fences if not f.network for c in f.commands if c.is_frisk]
        self.assertGreaterEqual(len(run), 8)

    def test_every_pasted_output_is_what_the_commands_print_now(self) -> None:
        diffs = differences(self.fences, self.tmp)
        self.assertEqual(diffs, [], "docs/WALKTHROUGH.md has stale output:\n" + "\n\n".join(diffs))

    def test_a_changed_pasted_output_line_is_a_difference(self) -> None:
        edited = self.text.replace("verdict:   PASS    0 blocking", "verdict:   PASS    9 blocking", 1)
        self.assertNotEqual(edited, self.text)
        diffs = differences(parse(edited), self.tmp)
        self.assertEqual(len(diffs), 1)
        self.assertIn("9 blocking", diffs[0])

    def test_a_frisk_command_with_no_pasted_output_is_a_problem(self) -> None:
        fences = parse("```console\n$ frisk examples/clean-skill\n```\n")
        self.assertEqual(len(problems(fences)), 1)
        self.assertIn("no pasted output", problems(fences)[0])

    def test_a_fence_with_no_command_is_a_problem(self) -> None:
        self.assertEqual(problems([Fence([], False)]), ["fence 1 has no command"])

    def test_the_network_marker_cannot_hide_a_frisk_command(self) -> None:
        fences = parse(f"{NETWORK}\n```console\n$ frisk --version\nfrisk 1.0.0\n```\n")
        self.assertTrue(fences[0].network)
        self.assertIn("marked network", problems(fences)[0])

    def test_normalising_hides_temp_directories_and_timings_but_not_the_version(self) -> None:
        got = normalise(f"frisk 1.2.3\nscanned in 0.12s, 35 ms at {self.tmp}/x  \n", [self.tmp])
        self.assertEqual(got, "frisk 1.2.3\nscanned in <time>, <time> at <tmp>/x")

    def test_a_command_that_never_ran_is_a_difference(self) -> None:
        fences = parse("```console\n$ echo hi\nhi\n$ frisk --version\nfrisk 0.0.0\n```\n")
        with mock.patch.object(sys.modules[__name__], "run_walkthrough",
                               return_value=(fences[0].commands, {0: "hi\n"})):
            diffs = differences(fences, self.tmp)
        self.assertEqual(len(diffs), 1)
        self.assertIn("frisk --version", diffs[0])
        self.assertIn("did not run", diffs[0])


if __name__ == "__main__":
    unittest.main()
