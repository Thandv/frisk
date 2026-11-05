"""The docs name only what exists: commands, flags, environment variables, files, modules, versions.

Read: README.md, STATUS.md, CONTRIBUTING.md, SECURITY.md, RELEASING.md and docs/**/*.md.
- A command in code (an inline span or a fence line) is `frisk`, a console script from
  pyproject.toml, or `frisk-scan` (the PyPI name, and the Foreman wrapper frisk does not
  ship); `frisk WORD` names a subcommand cli.main dispatches (or a target in the repository).
- Every `--flag` is an option string of one of the CLI's real argparse parsers (read from
  the parsers, so a flag renamed in the code fails here), or one of FOREIGN's other tools'.
- Every FRISK_* name is read by the code: a string literal of exactly that name in
  src/frisk, or `$NAME` in scripts/*.sh or action.yml.
- A repository path in code (scripts/, src/, tests/, docs/, examples/, changes/, .github/)
  exists, and a `:N` or `:N-M` line reference is within the file.
- A `frisk.x.y` name in code imports (a module, then attributes).
- STATUS.md's version is __version__, its next release is CHANGELOG.md's Unreleased
  heading, its command list is exactly the console scripts and subcommands, and every frisk
  version the docs name has a CHANGELOG heading.
Each check is shown to catch a planted case, in memory.
Run: PYTHONPATH=src python3 -B -m unittest discover -s tests
"""
from __future__ import annotations

import argparse
import contextlib
import importlib
import re
import tokenize
import unittest
from pathlib import Path
from unittest import mock

from _pyproject import load_pyproject
from _subproc import REPO
from frisk import __version__, cli

INLINE = re.compile(r"`([^`\n]+)`")
FLAG = re.compile(r"(?<![\w-])--[a-z][a-z0-9-]*")
ENV = re.compile(r"\bFRISK_[A-Z0-9_]+")
REPO_PATH = re.compile(r"^(?:\./)?((?:scripts|src|tests|docs|examples|changes|\.github)(?:/[\w.-]*)*)"
                       r"(?::(\d+)(?:-(\d+))?)?$")
MODULE = re.compile(r"\bfrisk(?:\.[a-z_][a-z0-9_]*)+")
SEPARATORS = {"|", "||", "&&", ";", "exec"}
# Flags of other tools that the docs quote, never frisk's: tool and reason.
FOREIGN = {
    "--api-key": "an example MCP server argument (README: secrets in a lockfile)",
    "--keyfile": "an example MCP server argument (README: secrets in a lockfile)",
    "--directory": "uv run", "--project": "uv run", "--python": "uvx", "--from": "uvx",
    "--spec": "pipx run", "--registry": "npx",
    "--no-recurse-submodules": "git clone, as frisk runs it",
    "--check": "scripts/gen_rules_doc.py and scripts/gen_readme_demo.py",
    "--recursive": "rm, in a rule's description", "--force": "rm, in a rule's description",
}
# Names that look like a frisk name but are not one.
NOT_ENV = {"FRISK_COMMAND": "the wrapper template's first argument, not an environment variable"}
NOT_FILES = {
    "docs/reviews/": "docs/threat-model.md says there is no such directory",
    "examples/foo/SKILL.md": "an illustrative path in docs/adr/0001-finding-paths.md",
}
FILE_SUFFIXES = {"sarif", "json", "log", "txt", "yml", "md"}
SHIPPED_ELSEWHERE = {"frisk-scan": "the PyPI package name, and Foreman's wrapper, which frisk does not ship"}


def docs() -> list[Path]:
    names = ("README.md", "STATUS.md", "CONTRIBUTING.md", "SECURITY.md", "RELEASING.md")
    return [REPO / n for n in names] + sorted((REPO / "docs").rglob("*.md"))


def split_fences(text: str) -> tuple[str, list[str]]:
    """(the text outside fences, the lines inside them), in one pass over the lines.

    A fence opens with a line starting ``` or ~~~ and closes at a line of the same marker and
    optional spaces; an unclosed fence runs to the end, as CommonMark has it."""
    prose: list[str] = []
    fenced: list[str] = []
    marker = ""
    for line in text.splitlines():
        if marker:
            if line.rstrip(" \t") == marker:
                marker = ""
            else:
                fenced.append(line)
        elif line.startswith(("```", "~~~")):
            marker = line[:3]
        else:
            prose.append(line)
    return "\n".join(prose), fenced


def code_segments(text: str) -> list[str]:
    """Each inline code span outside fences, and each line inside a fence."""
    prose, fenced = split_fences(text)
    return [line.strip() for line in fenced if line.strip()] + INLINE.findall(prose)


def commands(segment: str) -> list[list[str]]:
    """The commands in a code segment: its words, split at pipes, `&&`, `;` and `exec`."""
    words = segment[2:].split() if segment.startswith("$ ") else segment.split()
    out: list[list[str]] = [[]]
    for w in words:
        if w in SEPARATORS:
            out.append([])
        else:
            out[-1].append(w)
    return [c for c in out if c]


def console_scripts() -> set[str]:
    return set(load_pyproject()["project"]["scripts"])


def subcommands() -> set[str]:
    """The words cli.main dispatches on as argv[0]."""
    return set(re.findall(r'argv\[0\] == "(\w+)"', Path(cli.__file__).read_text(encoding="utf-8")))


class _Parsed(Exception):
    pass


def frisk_flags() -> set[str]:
    """The long option strings of every parser the CLI builds: a scan, lock, verify and proxy."""
    parsers: list[argparse.ArgumentParser] = []

    def grab(self: argparse.ArgumentParser, *args: object, **kwargs: object) -> None:
        parsers.append(self)
        raise _Parsed

    with mock.patch.object(argparse.ArgumentParser, "parse_args", grab):
        for argv in (["x"], ["lock"], ["verify"], ["proxy", "--", "x"]):
            with contextlib.suppress(_Parsed):
                cli.main(argv)
    assert len(parsers) == 4, parsers
    return {o for p in parsers for a in p._actions for o in a.option_strings if o.startswith("--")}


def env_reads() -> set[str]:
    """FRISK_* names the code reads: exact string literals in src/frisk, `$NAME` in shell."""
    found: set[str] = set()
    for path in sorted((REPO / "src" / "frisk").rglob("*.py")):
        with path.open("rb") as fh:
            for tok in tokenize.tokenize(fh.readline):
                if tok.type == tokenize.STRING and re.fullmatch(r"""(['"])FRISK_[A-Z0-9_]+\1""", tok.string):
                    found.add(tok.string[1:-1])
    for path in [*sorted((REPO / "scripts").glob("*.sh")), REPO / "action.yml"]:
        found.update(re.findall(r"\$\{?(FRISK_[A-Z0-9_]+)", path.read_text(encoding="utf-8")))
    return found


def bad_commands(text: str, scripts: set[str], subs: set[str]) -> list[str]:
    bad = []
    for segment in code_segments(text):
        for cmd in commands(segment):
            for word in cmd:
                if re.fullmatch(r"frisk-[a-z][a-z-]*", word) and word not in scripts | set(SHIPPED_ELSEWHERE):
                    bad.append(f"no command {word}")
            word = cmd[1] if cmd[0] == "frisk" and len(cmd) > 1 else ""
            # A bare word is a subcommand, unless it is a target in the repository (`frisk examples`).
            if re.fullmatch(r"[a-z][a-z-]*", word) and word not in subs and not (REPO / word).exists():
                bad.append(f"no subcommand frisk {word}")
    return bad


def bad_flags(text: str, flags: set[str]) -> list[str]:
    return sorted({f for f in FLAG.findall(text) if f not in flags and f not in FOREIGN})


def bad_env(text: str, reads: set[str]) -> list[str]:
    return sorted({n for n in ENV.findall(text) if n not in reads and n not in NOT_ENV})


def bad_files(text: str) -> list[str]:
    bad = []
    for segment in code_segments(text):
        for word in segment.split():
            word = word.strip("\"'(),;").split("#", 1)[0]
            m = REPO_PATH.match(word)
            if m is None or word in NOT_FILES:
                continue
            path = REPO / m.group(1)
            if not path.exists():
                bad.append(f"{word}: no such file")
            elif m.group(2):
                last = int(m.group(3) or m.group(2))
                lines = len(path.read_text(encoding="utf-8").splitlines())
                if last > lines:
                    bad.append(f"{word}: {path.name} has {lines} lines")
    return bad


def resolves(name: str) -> bool:
    """`frisk.a.b`: import the longest module prefix, then get the rest as attributes."""
    parts = name.split(".")
    for i in range(len(parts), 0, -1):
        try:
            obj: object = importlib.import_module(".".join(parts[:i]))
        except ImportError:
            continue
        for attr in parts[i:]:
            if not hasattr(obj, attr):
                return False
            obj = getattr(obj, attr)
        return True
    return False


def bad_modules(text: str) -> list[str]:
    bad = []
    for segment in code_segments(text):
        for name in MODULE.findall(segment):
            if name.rsplit(".", 1)[-1] not in FILE_SUFFIXES and not resolves(name):
                bad.append(f"{name}: does not import")
    return bad


def changelog_versions() -> list[str]:
    return re.findall(r"^## (\d+\.\d+\.\d+)\b", (REPO / "CHANGELOG.md").read_text(encoding="utf-8"), re.MULTILINE)


def unreleased() -> str:
    m = re.search(r"^## (\d+\.\d+\.\d+) — Unreleased$", (REPO / "CHANGELOG.md").read_text(encoding="utf-8"),
                  re.MULTILINE)
    assert m is not None, "CHANGELOG.md has no Unreleased heading"
    return m.group(1)


def frisk_versions(text: str, status: bool) -> set[str]:
    """Versions of frisk a doc names: pins, tags, `__version__` and `frisk X`; in STATUS.md, all
    but Python's."""
    patterns = [r"frisk-scan==(\d+\.\d+\.\d+)", r"\bv(\d+\.\d+\.\d+)\b", r"__version__ = \"(\d+\.\d+\.\d+)\"",
                r"\bfrisk (\d+\.\d+\.\d+)\b"]
    if status:
        patterns.append(r"(?<!Python )(?<![\d.])(\d+\.\d+\.\d+)\b")
    return {v for p in patterns for v in re.findall(p, text)}


def status_facts(text: str) -> dict[str, str]:
    """The `- Name: value` lines of STATUS.md's Facts section, each joined onto one line."""
    section = text.split("\n## Facts\n", 1)[1].split("\n## ", 1)[0]
    return {m.group(1): " ".join(m.group(2).split())
            for m in re.finditer(r"^- ([^:\n]+): (.*?)(?=^- |\Z)", section, re.MULTILINE | re.DOTALL)}


class TestNames(unittest.TestCase):
    def setUp(self) -> None:
        self.scripts, self.subs = console_scripts(), subcommands()

    def test_the_cli_is_what_this_test_expects(self) -> None:
        self.assertEqual(self.scripts, {"frisk", "frisk-mcp"})
        self.assertEqual(self.subs, {"lock", "verify", "proxy"})
        self.assertNotIn("frisk-scan", self.scripts)  # the docs say no frisk-scan command ships
        self.assertEqual(set(FOREIGN) & frisk_flags(), set())

    def test_commands_exist(self) -> None:
        for doc in docs():
            with self.subTest(doc=str(doc.relative_to(REPO))):
                self.assertEqual(bad_commands(doc.read_text(encoding="utf-8"), self.scripts, self.subs), [])

    def test_flags_are_real_parser_options(self) -> None:
        flags = frisk_flags()
        for doc in docs():
            with self.subTest(doc=str(doc.relative_to(REPO))):
                self.assertEqual(bad_flags(doc.read_text(encoding="utf-8"), flags), [])

    def test_environment_variables_are_read_by_the_code(self) -> None:
        reads = env_reads()
        for doc in docs():
            with self.subTest(doc=str(doc.relative_to(REPO))):
                self.assertEqual(bad_env(doc.read_text(encoding="utf-8"), reads), [])

    def test_files_and_line_references_exist(self) -> None:
        for doc in docs():
            with self.subTest(doc=str(doc.relative_to(REPO))):
                self.assertEqual(bad_files(doc.read_text(encoding="utf-8")), [])

    def test_modules_import(self) -> None:
        for doc in docs():
            with self.subTest(doc=str(doc.relative_to(REPO))):
                self.assertEqual(bad_modules(doc.read_text(encoding="utf-8")), [])


class TestPlanted(unittest.TestCase):
    """Each check catches a wrong name, in memory."""

    def test_a_missing_command_or_subcommand(self) -> None:
        text = "Run `frisk scan x`, `frisk-proxy -- y` and\n\n```bash\n$ frisk lock\nfrisk-lint . | frisk-mcp\n```\n"
        self.assertEqual(bad_commands(text, console_scripts(), subcommands()),
                         ["no command frisk-lint", "no subcommand frisk scan", "no command frisk-proxy"])

    def test_a_flag_renamed_in_the_code(self) -> None:
        flags = frisk_flags()
        self.assertIn("--on-change", flags)
        self.assertEqual(bad_flags("Use `--on-change drop` or --fail-on never.", flags - {"--on-change"}),
                         ["--on-change"])
        self.assertEqual(bad_flags("Use `--no-pin` and --fail-on.", flags), ["--no-pin"])

    def test_an_environment_variable_the_code_does_not_read(self) -> None:
        reads = env_reads()
        self.assertIn("FRISK_MCP_NO_NETWORK", reads)
        self.assertIn("FRISK_VERIFY_PYTHONS", reads)
        self.assertEqual(bad_env("Set FRISK_MCP_ROOTS and FRISK_MCP_ROOT.", reads), ["FRISK_MCP_ROOT"])

    def test_a_missing_file_or_line(self) -> None:
        text = "See `scripts/verify.sh`, `scripts/nope.sh`, `src/frisk/cli.py:99999` and `docs/rules.md#x`."
        self.assertEqual(bad_files(text), ["scripts/nope.sh: no such file", "src/frisk/cli.py:99999: cli.py has "
                                           f"{len((REPO / 'src/frisk/cli.py').read_text().splitlines())} lines"])

    def test_a_missing_module(self) -> None:
        self.assertEqual(bad_modules("`python -m frisk.cli`, `frisk.engine.reroot`, `frisk.engine.nope`, "
                                     "`frisk.scanner`, `frisk.sarif`"),
                         ["frisk.engine.nope: does not import", "frisk.scanner: does not import"])

    def test_fences_split_by_line(self) -> None:
        self.assertEqual(split_fences("a `x`\n```bash\nfrisk lock\n```  \nb\n~~~\nc\n```\nd"),
                         ("a `x`\nb", ["frisk lock", "c", "```", "d"]))

    def test_a_wrong_version(self) -> None:
        self.assertEqual(frisk_versions("pin `frisk-scan==0.4.0`, tag v9.9.9, Python 3.9.6, SARIF 2.1.0", False),
                         {"0.4.0", "9.9.9"})
        self.assertEqual(frisk_versions("Python 3.9.6; on PyPI: 0.1.0", True), {"0.1.0"})


class TestStatus(unittest.TestCase):
    def setUp(self) -> None:
        self.text = (REPO / "STATUS.md").read_text(encoding="utf-8")
        self.facts = status_facts(self.text)

    def test_version_is_the_source_version(self) -> None:
        self.assertEqual(re.match(r"`([^`]+)`", self.facts["Version in the source"]).group(1),  # type: ignore[union-attr]
                         __version__)

    def test_next_release_is_the_unreleased_changelog_heading(self) -> None:
        self.assertEqual(re.match(r"`([^`]+)`", self.facts["Next release"]).group(1), unreleased())  # type: ignore[union-attr]

    def test_commands_are_exactly_the_cli(self) -> None:
        line = self.facts["Commands"].split(". There is no", 1)[0]
        spans = INLINE.findall(line)
        self.assertEqual({s for s in spans if " " not in s}, console_scripts())
        self.assertEqual({s.split()[1] for s in spans if s.startswith("frisk ")}, subcommands())

    def test_every_frisk_version_named_has_a_changelog_heading(self) -> None:
        known = set(changelog_versions())
        self.assertIn(__version__, known)
        for doc in docs():
            with self.subTest(doc=str(doc.relative_to(REPO))):
                named = frisk_versions(doc.read_text(encoding="utf-8"), doc.name == "STATUS.md")
                self.assertEqual(sorted(named - known), [])

    def test_owner_held_items_are_listed(self) -> None:
        section = self.text.split("\n## Owner-held items\n", 1)[1].split("\n## ", 1)[0]
        for item in ("Release 0.3.0", "A pinned install", "Switch on the proxy", "Switch on Foreman's scanner",
                     "Keep a real-use log"):
            self.assertIn(f"**{item}**", section)

    def test_a_wrong_status_fact_is_caught(self) -> None:
        facts = status_facts("# S\n\n## Facts\n\n- Version in the source: `9.9.9`\n  (x).\n- Next release: `0.3.0`\n"
                             "\n## Next\n")
        self.assertEqual(facts, {"Version in the source": "`9.9.9` (x).", "Next release": "`0.3.0`"})
        self.assertNotEqual(facts["Version in the source"][1:6], __version__)


if __name__ == "__main__":
    unittest.main()
