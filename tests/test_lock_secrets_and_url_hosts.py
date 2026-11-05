"""Review regressions for FR-FX1 (independent review on-top).

Each test drives a hole the review found through the CLI, the lock or the redactor: the
attack input is now handled, and a matching legitimate input still works. Every path lives
in a temp dir with HOME patched to a directory inside it, so no real config or cache is
read. Canaries are assembled at runtime, hosts use the .invalid TLD, nothing is executed
and nothing touches the network.
Run: PYTHONPATH=src python3 -B -m unittest discover -s tests
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from _home import fake_home
from frisk import pin
from frisk.cli import main
from frisk.debug import redact
from frisk.sources import _launch_digest

CANARY = "c4n" + "ary-" + "f1x1" + "a7e5"


def run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with mock.patch("frisk.report.use_color", return_value=False), contextlib.redirect_stdout(out), \
            contextlib.redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class ReviewCase(unittest.TestCase):
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


class RedactionTimeTest(ReviewCase):
    """sev 5: the redactor matched a key/token/secret/password/authorization/cookie name from
    each occurrence and scanned the rest of its word every time, so a long word holding many
    names and no '=' took quadratic time. Since FR-FX1 10 every value of every audited server
    passes through it (the launch digest is made when the config is parsed): one 64 KiB
    argument made 'frisk --mcp-config' take 49 s (main: 0.16 s), 1 MiB about three hours, in a
    scan, a lock and a verify alike. CPU time, so machine load does not matter; the linear
    check takes milliseconds, so 2 s is a wide margin."""

    WORDS = (("key", "key" * (1 << 15)), ("Token", "Token" * (1 << 14)), ("api_key_", "api_key_" * (1 << 13)))

    def test_a_long_run_of_names_is_redacted_in_linear_time(self) -> None:
        for label, word in self.WORDS:
            with self.subTest(label):
                t0 = time.process_time()
                self.assertEqual(redact(word), word)
                self.assertEqual(redact(word + "=" + CANARY), word + "=[REDACTED]")
                self.assertLess(time.process_time() - t0, 2.0)

    def test_a_config_holding_one_is_audited_in_linear_time(self) -> None:
        self.entry(self.node(args=[str(self.server), self.WORDS[0][1]]))
        t0 = time.process_time()
        code, out, _err = run(["--mcp-config", str(self.cfg)])
        self.assertLess(time.process_time() - t0, 2.0)
        self.assertEqual(code, 0)
        self.assertIn("[PASS ] srv", out)

    def test_a_name_is_still_found_anywhere_in_its_word(self) -> None:
        # The name is now matched from the start of its word: the same values are redacted.
        for text, shown in (("--api-key=" + CANARY, "--api-key=[REDACTED]"),
                            ("apikey=" + CANARY, "apikey=[REDACTED]"),
                            ("-Dapi.key=" + CANARY, "-Dapi.key=[REDACTED]"),
                            ('{"api_key": "' + CANARY + '"}', '{"api_key": "[REDACTED]'),
                            ("monkey=" + CANARY, "monkey=[REDACTED]"),
                            ("key-id=" + CANARY, "key-id=" + CANARY),
                            ("sk-abc_key=" + CANARY, "[REDACTED]=" + CANARY),
                            # a word that starts like a token is the token, also with a name in it
                            ("gh" + "p_abckey=" + CANARY, "[REDACTED]=" + CANARY)):
            with self.subTest(text.replace(CANARY, "<canary>")):
                self.assertEqual(redact(text), shown)



class PinnedRedactionTest(ReviewCase):
    """sev 4: FR-FX1 10 hashes a value after redacting it with the debug pattern, whose secret
    ran to the next whitespace (or, in a URL, over anything but '/?#' up to the last '@'). So
    a change inside that span was not drift, and the span could hold what decides what runs: a
    shell command after ';' or in '$(...)', the next entries of a path list after 'name:', the
    rest of a compact JSON argument, an option after 'token=basic ', a host after a backslash
    (which WHATWG URL parsers, pip and uv read as the end of the host). Each of these was
    DRIFT on main or before FR-FX1 10 and 'no drift' after it. A secret there now ends at the
    first character a shell, a path list, an option list, JSON or a URL host part reads."""

    def env(self, name: str, value: str) -> dict:
        return self.node(env={name: value})

    def git_config(self, key: str, value: str) -> dict:
        return self.node(env={"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": key, "GIT_CONFIG_VALUE_0": value})

    def sh(self, script: str) -> dict:
        return {"command": "sh", "args": ["-c", script]}

    def test_a_change_after_a_secret_is_drift(self) -> None:
        run_payload = "touch${IFS}/tmp/frisk-review-" + CANARY  # runs where a shell reads the value
        cases = {
            "GIT_SSH_COMMAND: a command after an ssh option named like a key": (
                self.env("GIT_SSH_COMMAND", "ssh -o StrictHostKeyChecking=no"),
                self.env("GIT_SSH_COMMAND", "ssh -o StrictHostKeyChecking=no;" + run_payload), "GIT_SSH_COMMAND"),
            "GIT_SSH_COMMAND: the library ssh loads": (
                self.env("GIT_SSH_COMMAND", "ssh -o SecurityKeyProvider=/usr/lib/libsk.so"),
                self.env("GIT_SSH_COMMAND", "ssh -o SecurityKeyProvider=/tmp/evil.so"), "GIT_SSH_COMMAND"),
            "PYTHONPATH: the entries after a directory named like a token": (
                self.env("PYTHONPATH", "/srv/tokenizers:/srv/app"),
                self.env("PYTHONPATH", "/srv/tokenizers:/tmp/evil"), "PYTHONPATH"),
            "NODE_PATH: the entries after a directory named like a key": (
                self.env("NODE_PATH", "/opt/monkey:/opt/app/node_modules"),
                self.env("NODE_PATH", "/opt/monkey:/tmp/evil"), "NODE_PATH"),
            "LD_LIBRARY_PATH: the entries after a directory named like a secret": (
                self.env("LD_LIBRARY_PATH", "/usr/lib/libsecret:/opt/vendor/lib"),
                self.env("LD_LIBRARY_PATH", "/usr/lib/libsecret:/tmp/evil"), "LD_LIBRARY_PATH"),
            "a credential helper: a command substitution as the password": (
                self.git_config("credential.helper", "!f() { echo username=bot; echo password=s3cr3t; }; f"),
                self.git_config("credential.helper", "!f() { echo username=bot; echo password=$(" + run_payload
                                + "); }; f"), "GIT_CONFIG_VALUE_0"),
            "JAVA_TOOL_OPTIONS: an option after 'token=basic '": (
                self.env("JAVA_TOOL_OPTIONS", "-Dapi.token=basic -Xmx512m"),
                self.env("JAVA_TOOL_OPTIONS", "-Dapi.token=basic -javaagent:/tmp/evil.jar"), "JAVA_TOOL_OPTIONS"),
            "sh -c: a command after an assignment named like a key": (
                self.sh("API_KEY=abc exec node /srv/app/server.js"),
                self.sh("API_KEY=abc;" + run_payload + "& exec node /srv/app/server.js"), "launch"),
            "sh -c: a command substitution as a Bearer token": (
                self.sh("exec mcp-proxy --header 'Authorization: Bearer abc' https://h.example.invalid/sse"),
                self.sh("exec mcp-proxy --header 'Authorization: Bearer $(" + run_payload + ")' "
                        "https://h.example.invalid/sse"), "launch"),
            "sh -c: a command substitution as a URL's user": (
                self.sh("git clone https://tok@github.com/acme/x x && exec node x/server.js"),
                self.sh("git clone https://$(touch${IFS}pwned)@github.com/acme/x x && exec node x/server.js"),
                "launch"),
            "the rest of a compact JSON argument after an apiKey": (
                self.node(args=[str(self.server), '--config={"apiKey":"abc","plugin":"/srv/p.js"}']),
                self.node(args=[str(self.server), '--config={"apiKey":"abc","plugin":"/tmp/evil.js"}']), "launch"),
            "a URL argument: the host before a backslash, where clients end the host": (
                {"command": "npx", "args": ["-y", "mcp-remote", "https://user:tok@mcp.example.invalid/sse"]},
                {"command": "npx", "args": ["-y", "mcp-remote", "https://evil.example.invalid\\@mcp.example.invalid/sse"]},
                "launch"),
        }
        for label, (before, after, named) in cases.items():
            with self.subTest(label):
                self.assert_drift(before, after, named)

    def test_each_character_that_ends_a_secret_is_needed(self) -> None:
        # One character each: a change that only it separates from the secret is drift.
        ssh, sh = (lambda v: self.env("GIT_SSH_COMMAND", "ssh -o StrictHostKeyChecking=" + v)), self.sh
        cases = {
            ";": (ssh("no"), ssh("no;reboot"), "GIT_SSH_COMMAND"),
            "|": (ssh("no"), ssh("no|reboot"), "GIT_SSH_COMMAND"),
            "&": (sh("API_KEY=abc exec node /srv/app/server.js"),
                  sh("API_KEY=abc&reboot& exec node /srv/app/server.js"), "launch"),
            "$( )": (self.git_config("credential.helper", "!f() { echo password=s3cr3t; }; f"),
                     self.git_config("credential.helper", "!f() { echo password=$(reboot); }; f"),
                     "GIT_CONFIG_VALUE_0"),
            "a backquote": (self.git_config("credential.helper", "!f() { echo password=s3cr3t; }; f"),
                            self.git_config("credential.helper", "!f() { echo password=`reboot`; }; f"),
                            "GIT_CONFIG_VALUE_0"),
            ":": (self.env("PYTHONPATH", "/srv/tokenizers:lib:app"),
                  self.env("PYTHONPATH", "/srv/tokenizers:lib:evil"), "PYTHONPATH"),
            "a quote and ',' in JSON": (self.node(args=[str(self.server), '--config={"apiKey":"abc","plugin":"p.js"}']),
                                        self.node(args=[str(self.server), '--config={"apiKey":"abc","plugin":"e.js"}']),
                                        "launch"),
            "$( ) as a URL's user": (sh("git clone https://tok@github.com/acme/x x && exec node x/server.js"),
                                     sh("git clone https://$(reboot)@github.com/acme/x x && exec node x/server.js"),
                                     "launch"),
            "an option after a name's Basic": (
                self.env("JAVA_TOOL_OPTIONS", "-Dapi.token=basic -Xmx512m"),
                self.env("JAVA_TOOL_OPTIONS", "-Dapi.token=basic -Djava.system.class.loader=evil.Loader"),
                "JAVA_TOOL_OPTIONS"),
            "an option after a lone Basic": (
                self.env("JAVA_TOOL_OPTIONS", "-Dauth=basic -Xmx512m"),
                self.env("JAVA_TOOL_OPTIONS", "-Dauth=basic -Djava.system.class.loader=evil.Loader"),
                "JAVA_TOOL_OPTIONS"),
        }
        for label, (before, after, named) in cases.items():
            with self.subTest(label):
                self.assert_drift(before, after, named)

    def test_a_secret_beside_them_is_still_never_stored(self) -> None:
        cases = {
            "a password before ';' in a credential helper":
                lambda s: self.git_config("credential.helper",
                                          "!f() { echo username=bot; echo password=" + s + "; }; f"),
            "an assignment before a command in sh -c":
                lambda s: self.sh("API_KEY=" + s + " exec node /srv/app/server.js"),
            "a URL's user:password in sh -c":
                lambda s: self.sh("git clone https://bot:" + s + "@github.com/acme/x x && exec node x/server.js"),
            "a Bearer token in a quoted header":
                lambda s: self.sh("exec mcp-proxy --header 'Authorization: Bearer " + s + "' https://h.example.invalid/sse"),
            "an apiKey in a compact JSON argument":
                lambda s: self.node(args=[str(self.server), '--config={"apiKey":"' + s + '","plugin":"/srv/p.js"}']),
            "an ssh option named like a key":
                lambda s: self.env("GIT_SSH_COMMAND", "ssh -o StrictHostKeyChecking=" + s + " -i /keys/deploy"),
            "-Dpassword before 'token=basic' and an option":
                lambda s: self.env("JAVA_TOOL_OPTIONS", "-Dpassword=" + s + " -Dapi.token=basic -Xmx512m"),
        }
        for label, spec in cases.items():
            with self.subTest(label):
                self.assert_rotation_is_no_drift(spec)



class UrlHostTest(ReviewCase):
    """sev 4: a URL is pinned by the host a client connects to. (1) WHATWG URL parsers (node,
    so Claude Code and npm), pip's requests/urllib3 and uv end the host of an http(s) URL at a
    backslash, while urlsplit does not: 'https://evil\\@pypi.example/simple' was pinned as
    'https://pypi.example/simple', so swapping an index, find-links or server URL to another
    host was no drift (FR-FX1 7 and 8; for a server url since FR-E4). (2) FR-FX1 10 pinned a
    server URL with an '@' after its host (https://server.smithery.ai/@owner/server/mcp, an
    email in the query) only by its length class, so another host or owner of the same length
    class was no drift; main hashed it whole (DRIFT)."""

    EVIL = "https://evil.example.invalid\\@"

    def test_a_backslash_in_the_host_part_is_drift(self) -> None:
        evil = self.EVIL
        cases = {
            "PIP_INDEX_URL": ("https://pypi.example.invalid/simple", evil + "pypi.example.invalid/simple"),
            "UV_INDEX": ("internal=https://pypi.example.invalid/simple",
                         "internal=" + evil + "pypi.example.invalid/simple"),
            "npm_config_registry": ("https://registry.example.invalid/", evil + "registry.example.invalid/"),
            "PIP_FIND_LINKS": ("https://wheels.example.invalid/x", evil + "wheels.example.invalid/x"),
        }
        for name, (before, after) in cases.items():
            with self.subTest(name):
                self.assert_drift(self.node(env={name: before}), self.node(env={name: after}), name)
        with self.subTest("a server url"):
            self.assert_drift({"url": "https://mcp.example.invalid/sse"}, {"url": evil + "mcp.example.invalid/sse"},
                              "launch")

    def test_the_audit_never_shows_a_host_the_client_does_not_use(self) -> None:
        self.entry({"url": self.EVIL + "mcp.example.invalid/sse"})
        code, out, err = run(["--mcp-config", str(self.cfg)])
        self.assertNotIn("mcp.example.invalid", out + err)
        self.assertIn("<unparsable URL>", out)

    def test_an_at_sign_after_the_host_does_not_hide_it(self) -> None:
        base = "https://server.example.invalid/@acme/github/mcp"
        for label, after in (("another host", "https://evil.example.invalid/@acme/github/mcp/x"),
                             ("another owner", "https://server.example.invalid/@evil/github/mcp"),
                             ("an email in the query", "https://evil.example.invalid/sse?user=dev@example.invalid")):
            with self.subTest(label):
                before = "https://mcp.example.invalid/sse?user=dev@example.invalid" if "email" in label else base
                self.assertEqual(len(before).bit_length(), len(after).bit_length())  # one length class
                self.assert_drift({"url": before}, {"url": after}, "launch")
        with self.subTest("a token in its query is still never stored"):
            self.assert_rotation_is_no_drift(lambda s: {"url": base + "?api_key=" + s})
        with self.subTest("hashed as main hashed it: the whole URL, which has nothing to drop"):
            shape = {"command": None, "args": None, "cwd": None, "type": None, "url": base,
                     "env": "NoneType", "headers": "NoneType"}
            expected = hashlib.sha256(json.dumps(shape, sort_keys=True).encode("utf-8")).hexdigest()
            self.assertEqual(_launch_digest({"url": base}), expected)



class GitConfigValueTest(ReviewCase):
    """sev 4: FR-FX1 8 pinned each word of a GIT_CONFIG_* value that holds '://' like an index
    URL (_url_pin): without its query and fragment, and as '<unparsable URL>' plus its length
    class when urlsplit cannot read it (a quoted URL, 'Name=https://...'). But git runs some
    of these values through the shell (core.sshCommand, a '!' credential helper, aliases,
    filters), where a query or a quoted word can hold a command, so changing one was no drift.
    The value is now pinned as written after the redaction, which still drops a URL's
    'user:token@'."""

    def helper(self, value: str) -> dict:
        return self.node(env={"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "credential.helper",
                              "GIT_CONFIG_VALUE_0": value})

    def test_a_command_in_a_url_word_is_drift(self) -> None:
        payload = "touch${IFS}/tmp/frisk-review-" + CANARY
        cases = {
            "in the query of a URL": (
                "!f() { curl -s https://vault.example.invalid/git-cred; }; f",
                "!f() { curl -s https://vault.example.invalid/git-cred;?$(" + payload + "); }; f"),
            "a quoted URL word of the same length class": (
                "!f() { curl -s 'https://vault.example.invalid/git/credential'; }; f",
                "!f() { curl -s 'https://vault.example.invalid/c'$(" + payload[:12] + "); }; f"),
            "a URL after 'Name='": ("!f() { env SRC=https://ci.example.invalid/run git-cred; }; f",
                                    "!f() { env SRC=https://$(touch${IFS}p)@ci.example.invalid/run git-cred; }; f"),
        }
        for label, (before, after) in cases.items():
            with self.subTest(label):
                self.assert_drift(self.helper(before), self.helper(after), "GIT_CONFIG_VALUE_0")

    def test_a_token_in_a_url_there_is_still_never_stored(self) -> None:
        cases = {
            "an insteadOf key": lambda s: self.node(env={"GIT_CONFIG_KEY_0": "url.https://x-access-token:" + s
                                                         + "@github.com/.insteadOf"}),
            "a quoted URL in a helper": lambda s: self.helper("!f() { curl -s 'https://bot:" + s
                                                              + "@vault.example.invalid/cred'; }; f"),
        }
        for label, spec in cases.items():
            with self.subTest(label):
                self.assert_rotation_is_no_drift(spec)


if __name__ == "__main__":
    unittest.main()
