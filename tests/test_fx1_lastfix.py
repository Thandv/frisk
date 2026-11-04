"""Review regressions for the FR-FX1 review's on-top (last-fix review).

Each test drives a hole through the CLI's lock and verify: the attack input is now drift, and
a matching legitimate input (a rotated token) still is not. Every path lives in a temp dir
with HOME patched to a directory inside it, so no real config or cache is read. Canaries are
assembled at runtime, hosts use the .invalid TLD, nothing is executed and nothing touches the
network.
Run: PYTHONPATH=src python3 -B -m unittest discover -s tests
"""
from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from _home import fake_home
from frisk import pin
from frisk.cli import main

CANARY = "c4n" + "ary-" + "1a57" + "f1x"


def run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with mock.patch("frisk.report.use_color", return_value=False), contextlib.redirect_stdout(out), \
            contextlib.redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class LastFixCase(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.home = self.tmp / "home"
        self.server = self.home / "srv" / "server.js"
        self.server.parent.mkdir(parents=True)
        self.server.write_text("console.log(1)\n", encoding="utf-8")
        fake_home(self, self.home)
        self.cfg = self.tmp / "mcp.json"
        self.lockfile = str(self.tmp / "lock.json")

    def entry(self, spec: dict) -> None:
        self.cfg.write_text(json.dumps({"mcpServers": {"srv": spec}}), encoding="utf-8")

    def node(self, **extra: object) -> dict:
        return {"command": "node", "args": [str(self.server)], **extra}

    def lock(self) -> bytes:
        self.assertEqual(run(["lock", "--mcp-config", str(self.cfg), "--lockfile", self.lockfile])[0], 0)
        return Path(self.lockfile).read_bytes()

    def row(self) -> dict:
        (row,) = [r for r in pin.verify_lock(pin.read_lock(self.lockfile)) if r["entry"] == f"{self.cfg}::srv"]
        return row

    def assert_drift(self, before: dict, after: dict, named: str) -> None:
        """Lock `before`, change it to `after`: DRIFT naming the launch or the variable."""
        self.entry(before)
        self.lock()
        self.entry(after)
        row = self.row()
        self.assertEqual(row["status"], "DRIFT")
        if named == "launch":
            self.assertEqual(row.get("launch"), "changed")
        else:
            self.assertEqual(row.get("env"), [named])

    def assert_rotation_is_no_drift(self, spec: object) -> None:
        """`spec` (a function of the secret): the lockfile holds nothing derived from it."""
        self.entry(spec(CANARY + "1"))  # type: ignore[operator]
        pinned = self.lock()
        self.assertNotIn(CANARY.encode(), pinned)
        self.entry(spec(CANARY + "2"))  # type: ignore[operator]
        self.assertEqual(self.row()["status"], "ok")
        self.assertEqual(self.lock(), pinned)


class BackslashHostTest(LastFixCase):
    """sev 3: the review's on-top pinned a URL with a backslash in its host part only by its
    length class, as unparsable. But node (so Claude Code and npm), uv and pip end an http(s)
    host part at a backslash: 'https://mcp.example\\sse' is fetched from mcp.example. So a
    config that already held such a URL (a server url, an index, registry or find-links
    variable) could swap its host for any other of the same length class with no drift, where
    FR-FX1 10 had pinned it as written (DRIFT). The host part now ends where those clients end
    it, so the host they connect to is pinned, and the backslash stays in the path."""

    GOOD, EVIL = "mcp.example.invalid", "evl.example.invalid"  # one length

    def test_the_host_before_a_backslash_is_pinned(self) -> None:
        rows = {
            "a server url": (lambda h: {"url": f"https://{h}\\sse"}, "launch"),
            "a server url with an '@' after the backslash": (
                lambda h: {"url": f"https://{h}\\@x.example.invalid/sse"}, "launch"),
            "PIP_INDEX_URL": (lambda h: self.node(env={"PIP_INDEX_URL": f"https://{h}\\simple"}), "PIP_INDEX_URL"),
            "UV_INDEX": (lambda h: self.node(env={"UV_INDEX": f"internal=https://{h}\\simple"}), "UV_INDEX"),
            "npm_config_registry": (lambda h: self.node(env={"npm_config_registry": f"https://{h}\\"}),
                                    "npm_config_registry"),
            "PIP_FIND_LINKS": (lambda h: self.node(env={"PIP_FIND_LINKS": f"https://{h}\\wheels"}), "PIP_FIND_LINKS"),
        }
        for label, (spec, named) in rows.items():
            with self.subTest(label):
                self.assertEqual(json.dumps(spec(self.GOOD)).replace(self.GOOD, self.EVIL), json.dumps(spec(self.EVIL)))
                self.assert_drift(spec(self.GOOD), spec(self.EVIL), named)

    def test_the_path_after_it_still_counts(self) -> None:
        self.assert_drift({"url": f"https://{self.GOOD}\\sse"}, {"url": f"https://{self.GOOD}\\mcp"}, "launch")
        self.assert_drift(self.node(env={"PIP_INDEX_URL": f"https://{self.GOOD}\\simple"}),
                          self.node(env={"PIP_INDEX_URL": f"https://{self.GOOD}\\simplx"}), "PIP_INDEX_URL")
        # the backslash stays in the path: pip fetches '/%5Csimple' there, not '/simple'
        self.assert_drift(self.node(env={"PIP_INDEX_URL": f"https://{self.GOOD}\\simple"}),
                          self.node(env={"PIP_INDEX_URL": f"https://{self.GOOD}/simple"}), "PIP_INDEX_URL")

    def test_a_token_there_is_still_never_stored(self) -> None:
        cases = {
            "a server url's user:token@": lambda s: {"url": f"https://bot:{s}@{self.GOOD}\\sse"},
            "an index url's user:token@": lambda s: self.node(env={"PIP_INDEX_URL": f"https://u:{s}@{self.GOOD}\\simple"}),
        }
        for label, spec in cases.items():
            with self.subTest(label):
                self.assert_rotation_is_no_drift(spec)

    def test_the_audit_still_shows_no_host_for_it(self) -> None:
        self.entry({"url": f"https://evil.example.invalid\\@{self.GOOD}/sse"})
        code, out, err = run(["--mcp-config", str(self.cfg)])
        self.assertNotIn(self.GOOD, out + err)
        self.assertIn("<unparsable URL>", out)


class VersionPinTest(LastFixCase):
    """sev 3: since FR-FX1 10 a value after a key/token/secret/password/authorization/cookie
    name and '=' is redacted before it is hashed, and the name is found anywhere in a word,
    so 'mcp-keycloak==1.0.0', 'tiktoken==0.7.0' or 'keyring==24.0' was pinned as
    'mcp-keycloak=[REDACTED]' and a changed version, which decides what code runs, was no
    drift (main: DRIFT). The review's on-top kept '=', '.' and digits in a secret, so it
    stayed. Where the package is not in the local cache (CI), the launch is all frisk lock
    pins of such a server. A name followed by '==', a comparison or a version pin, is no
    longer read as the start of a secret."""

    def test_a_changed_version_pin_is_drift(self) -> None:
        def uvx(spec: str) -> dict:
            return {"command": "uvx", "args": ["--from", spec, "mcp-keycloak"]}

        def sh(script: str) -> dict:
            return {"command": "sh", "args": ["-c", script]}

        cases = {
            "uvx --from": (uvx("mcp-keycloak==1.0.0"), uvx("mcp-keycloak==1.0.1")),
            "uv run --with": ({"command": "uv", "args": ["run", "--with", "tiktoken==0.7.0", str(self.server)]},
                              {"command": "uv", "args": ["run", "--with", "tiktoken==0.8.0", str(self.server)]}),
            "pipx run --spec": ({"command": "pipx", "args": ["run", "--spec", "keyring==24.0", "keyring"]},
                                {"command": "pipx", "args": ["run", "--spec", "keyring==25.1", "keyring"]}),
            "'===' arbitrary equality": (uvx("mcp-keycloak===1.0.0"), uvx("mcp-keycloak===6.6.6")),
            "pip install in sh -c": (sh("pip install mcp-secrets==1.0 && exec mcp-secrets"),
                                     sh("pip install mcp-secrets==6.6 && exec mcp-secrets")),
        }
        for label, (before, after) in cases.items():
            with self.subTest(label):
                self.assert_drift(before, after, "launch")

    def test_a_secret_after_one_equals_sign_is_still_never_stored(self) -> None:
        remote = ["-y", "mcp-remote", "https://h.example.invalid/sse", "--header"]
        cases = {
            "--api-key=": lambda s: self.node(args=[str(self.server), "--api-key=" + s]),
            "base64 padding after it": lambda s: self.node(args=[str(self.server), "--api-key=" + s + "=="]),
            "a cookie's name=value": lambda s: {"command": "npx", "args": [*remote, "Cookie: session=" + s]},
            "':=' as make writes it": lambda s: {"command": "make", "args": ["serve", "PASSWORD:=" + s]},
        }
        for label, spec in cases.items():
            with self.subTest(label):
                self.assert_rotation_is_no_drift(spec)


if __name__ == "__main__":
    unittest.main()
