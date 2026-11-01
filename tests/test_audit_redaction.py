"""No URL credential, query, fragment, header or env value reaches MCP audit output (AUD-S13).

The canary is assembled at runtime, hosts use the .invalid TLD, HOME is the temp dir,
nothing is executed and nothing touches the network.
Run: PYTHONPATH=src python3 -B -m unittest discover -s tests
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from _home import fake_home
from frisk import pin, report
from frisk.cli import main
from frisk.engine import ScanResult
from frisk.report import AuditRecord, audit_text
from frisk.sources import ServerRef, display_ref, display_target, display_url

CANARY = "c4n" + "ary-" + "51f0" + "e2d7"


def run(argv: list[str]) -> str:
    out = io.StringIO()
    with mock.patch("frisk.report._USE_COLOR", False), contextlib.redirect_stdout(out):
        main(argv)
    return out.getvalue()


def ref(kind: str, value: str) -> ServerRef:
    return ServerRef("s", kind, value, False)


class DisplayRefTest(unittest.TestCase):
    def test_url_keeps_scheme_host_and_port_only(self) -> None:
        # FR-E4 owner decision (N3): no path either (was: scheme, host, port and path).
        url = "https://user:" + CANARY + "@h.example.invalid:8443/a/b;p?token=" + CANARY + "#" + CANARY
        self.assertEqual(display_ref(ref("remote", url)), "https://h.example.invalid:8443/…")

    def test_a_url_with_nothing_after_its_host_is_shown_whole(self) -> None:
        for url in ("https://mcp.example.invalid", "https://mcp.example.invalid/"):
            with self.subTest(url=url):
                self.assertEqual(display_ref(ref("remote", url)), "https://mcp.example.invalid")

    def test_unparsable_remote_ref_is_not_shown(self) -> None:
        for value in ("http://[::1/sse?token=" + CANARY, "mcp.example.invalid/sse?token=" + CANARY,
                      "https:///path?token=" + CANARY, ""):
            with self.subTest(n=len(value)):
                self.assertEqual(display_ref(ref("remote", value)), "<unparsable URL>")

    def test_a_package_given_as_a_url_is_redacted_too(self) -> None:
        spec = "https://u:" + CANARY + "@registry.example.invalid/pkg.tgz?sig=" + CANARY
        # FR-E4 owner decision (N3): a URL shows its host only (was: its path too)
        self.assertEqual(display_ref(ref("package", spec)), "https://registry.example.invalid/…")

    def test_paths_commands_and_package_names_are_unchanged(self) -> None:
        for kind, value in (("unknown", "/nonexistent.invalid/bin/srv"), ("package", "@acme/weather-mcp@1.2.3"),
                            ("local", "/srv/app"), ("unknown", "?")):
            with self.subTest(value=value):
                self.assertEqual(display_ref(ref(kind, value)), value)

    def test_audit_text_shows_refs_only_through_display_ref(self) -> None:
        rec = AuditRecord(ref("remote", "https://raw.example.invalid/x"), ScanResult(), None)
        with mock.patch("frisk.report._USE_COLOR", False), \
                mock.patch.object(report, "display_ref", return_value="<shown>"):
            text = audit_text("cfg.json", [rec])
        self.assertIn("→ <shown>", text)
        self.assertNotIn("raw.example.invalid", text)


class AuditOutputTest(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        home = mock.patch.dict(os.environ, {"HOME": str(self.root)})
        home.start()
        self.addCleanup(home.stop)
        self.cfg = self.root / "mcp.json"
        self.cfg.write_text(json.dumps({"mcpServers": {
            "query": {"url": "https://q.example.invalid/sse?token=" + CANARY},
            "userinfo": {"url": "https://user:" + CANARY + "@u.example.invalid/mcp"},
            "fragment": {"url": "https://f.example.invalid/mcp#" + CANARY},
            "headers": {"url": "https://h.example.invalid/mcp", "headers": {"Authorization": "Bearer " + CANARY}},
            "env": {"command": "/nonexistent.invalid/bin/srv", "env": {"API_KEY": CANARY}},
            "pkg-url": {"command": "npx", "args": ["-y", "https://u:" + CANARY + "@r.example.invalid/p.tgz"]},
        }}), encoding="utf-8")

    def test_text_output_has_no_canary_and_keeps_scheme_host_path(self) -> None:
        out = run(["--mcp-config", str(self.cfg)])
        self.assertNotIn(CANARY, out)
        # FR-E4 owner decision (N3): URLs show their host only (was: their path too).
        for shown in ("https://q.example.invalid/…", "https://u.example.invalid/…", "https://f.example.invalid/…",
                      "https://h.example.invalid/…", "/nonexistent.invalid/bin/srv", "https://r.example.invalid/…"):
            with self.subTest(shown=shown):
                self.assertIn("→ " + shown + "\n", out)

    def test_json_output_has_no_canary(self) -> None:
        out = run(["--json", "--mcp-config", str(self.cfg)])
        json.loads(out)
        self.assertNotIn(CANARY, out)


class UserinfoDelimiterTest(unittest.TestCase):
    """FR-E4 fix DEFECT-1: an unencoded '#', '?' or '/' in a password cuts urlsplit's host
    part short; such a URL must show as '<unparsable URL>', never 'scheme://user:<secret>'."""

    SERVERS = {
        "hash": ("https://user:" + CANARY + "#x@hash.example.invalid/mcp", "<unparsable URL>"),
        "query": ("https://user:" + CANARY + "?x@query.example.invalid/mcp", "<unparsable URL>"),
        "slash": ("https://user:" + CANARY + "/x@slash.example.invalid/mcp", "<unparsable URL>"),
        "bare-token-slash": ("https://" + CANARY + "/x@token.example.invalid/mcp", "<unparsable URL>"),
        "pct-at": ("https://user%40corp:" + CANARY + "@pct.example.invalid/mcp", "https://pct.example.invalid/…"),
        "ipv6": ("https://user:" + CANARY + "@[::1]:8443/sse?t=" + CANARY, "https://[::1]:8443/…"),
        "ipv6-hash": ("https://user:" + CANARY + "#x@[::1]/sse", "<unparsable URL>"),
    }

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.cfg = Path(tmp.name) / "mcp.json"
        self.cfg.write_text(json.dumps({"mcpServers": {n: {"url": u} for n, (u, _) in self.SERVERS.items()}}),
                            encoding="utf-8")

    def test_display_ref_of_each_form(self) -> None:
        for name, (url, shown) in self.SERVERS.items():
            with self.subTest(name):
                self.assertEqual(display_ref(ref("remote", url)), shown)

    def test_no_output_format_shows_the_secret(self) -> None:
        for flags in ([], ["--json"], ["--sarif"], ["-q"]):
            with self.subTest(flags=flags):
                self.assertNotIn(CANARY, run([*flags, "--mcp-config", str(self.cfg)]))
        text = run(["--mcp-config", str(self.cfg)])
        self.assertIn("→ https://[::1]:8443/…\n", text)
        self.assertIn("→ https://pct.example.invalid/…\n", text)
        self.assertEqual(text.count("→ <unparsable URL>\n"), 5)

    def test_other_forms_that_hide_the_host_are_unparsable(self) -> None:
        for url in ("https://host.example.invalid:99999/x", "https://host.example.invalid:http/x",
                    "https://host.example.invalid/@scope/pkg"):  # an '@' after the host is ambiguous: hidden
            with self.subTest(url=url):
                self.assertEqual(display_ref(ref("remote", url)), "<unparsable URL>")


class HostOnlyTest(unittest.TestCase):
    """FR-E4 owner decision (N3): every URL frisk prints from a config is scheme://host[:port]
    plus '/…'; no path, parameters, query, fragment or credentials, in any output channel."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        fake_home(self)
        script = self.root / "srv" / "server.py"
        script.parent.mkdir()
        script.write_text('print("hi")\n', encoding="utf-8")
        self.cfg = self.root / "mcp.json"
        self.servers = {
            "path-token": {"url": "https://mcp.example.invalid/v1/" + CANARY + "/sse"},
            "jsessionid": {"url": "https://mcp.example.invalid/sse;jsessionid=" + CANARY},
            "host-param": {"url": "https://mcp.example.invalid;jsessionid=" + CANARY + "/sse"},
            "port-path": {"serverUrl": "https://mcp.example.invalid:8443/" + CANARY},
            "pkg-url": {"command": "npx", "args": ["-y", "https://r.example.invalid/" + CANARY + "/p.tgz"]},
            "beside": {"command": "python3", "args": [str(script)], "url": "https://b.example.invalid/" + CANARY},
        }
        self.cfg.write_text(json.dumps({"mcpServers": self.servers}), encoding="utf-8")
        self.lockfile = str(self.root / "lock.json")

    def outputs(self, argv: list[str]) -> tuple[str, str]:
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, {"FRISK_DEBUG": "1"}), mock.patch("frisk.report._USE_COLOR", False), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            main(argv)
        return out.getvalue(), err.getvalue()

    def test_the_forms(self) -> None:
        for url, shown in (
            ("https://mcp.example.invalid/v1/" + CANARY + "/sse", "https://mcp.example.invalid/…"),
            ("https://mcp.example.invalid/sse;jsessionid=" + CANARY, "https://mcp.example.invalid/…"),
            ("https://mcp.example.invalid?k=" + CANARY, "https://mcp.example.invalid/…"),
            ("https://mcp.example.invalid#" + CANARY, "https://mcp.example.invalid/…"),
            ("HTTPS://Mcp.Example.invalid:8443/x", "https://Mcp.Example.invalid:8443/…"),
            ("https://xn--mnchen-3ya.example.invalid/x", "https://xn--mnchen-3ya.example.invalid/…"),
            ("https://m\u00fcnchen.example.invalid/x", "https://m\u00fcnchen.example.invalid/…"),
            ("https://[::1]:8443/" + CANARY, "https://[::1]:8443/…"),
            ("https://mcp.example.invalid;jsessionid=" + CANARY + "/sse", "<unparsable URL>"),
            ("https://mcp.example.invalid%3B" + CANARY + "/sse", "<unparsable URL>"),
        ):
            with self.subTest(url=url.replace(CANARY, "<canary>")):
                self.assertEqual(display_url(url), shown)

    def test_no_channel_prints_a_path_or_parameter(self) -> None:
        for argv in ([], ["--json"], ["--sarif"], ["-q"]):
            with self.subTest(argv=argv):
                out, err = self.outputs([*argv, "--mcp-config", str(self.cfg)])
                self.assertNotIn(CANARY, out + err)
        text = self.outputs(["--mcp-config", str(self.cfg)])[0]
        for shown in ("https://mcp.example.invalid/…", "https://mcp.example.invalid:8443/…",
                      "https://r.example.invalid/…", "https://b.example.invalid/…", "<unparsable URL>"):
            self.assertIn(shown, text)

    def test_the_lock_hashes_the_same_url_as_before(self) -> None:
        # The launch digest keeps the path but no credentials, query or fragment, exactly the
        # string earlier builds hashed, so lockfiles written before host-only display verify.
        import hashlib
        from frisk.sources import _launch_digest
        shape = {"command": None, "args": None, "cwd": None, "type": None, "url": "https://h.example.invalid/v1/sse",
                 "env": "NoneType", "headers": "NoneType"}
        expected = hashlib.sha256(json.dumps(shape, sort_keys=True).encode("utf-8")).hexdigest()
        self.assertEqual(_launch_digest({"url": "https://u:p@h.example.invalid/v1/sse?k=1#f"}), expected)

    def test_lock_and_verify_print_no_path_and_still_pin_it(self) -> None:
        out, err = self.outputs(["lock", "--mcp-config", str(self.cfg), "--lockfile", self.lockfile])
        self.assertNotIn(CANARY, out + err + Path(self.lockfile).read_text(encoding="utf-8"))
        moved = dict(self.servers, **{"path-token": {"url": "https://mcp.example.invalid/v2/" + CANARY + "/sse"}})
        self.cfg.write_text(json.dumps({"mcpServers": moved}), encoding="utf-8")
        for argv in (["verify"], ["verify", "--json"]):
            out, err = self.outputs([*argv, "--lockfile", self.lockfile])
            self.assertNotIn(CANARY, out + err)
        (row,) = [r for r in pin.verify_lock(pin.read_lock(self.lockfile)) if r["status"] != "ok"]
        self.assertEqual((row["entry"], row["launch"]), (f"{self.cfg}::path-token", "changed"))


class FakeGit:
    """Stands in for subprocess.run in frisk.sources: records the URL of each clone, and
    either writes one file into the clone or fails with a message that echoes the URL."""

    def __init__(self, fail: bool = False) -> None:
        self.urls: list[str] = []
        self.fail = fail

    def __call__(self, argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess:
        self.urls.append(argv[-2])
        if self.fail:
            return subprocess.CompletedProcess(argv, 128, "", f"fatal: unable to access '{argv[-2]}/': denied")
        Path(argv[-1], "SKILL.md").write_text("hello\n", encoding="utf-8")
        return subprocess.CompletedProcess(argv, 0, "", "")


class GitTargetCredentialTest(unittest.TestCase):
    """FR-E4 owner decision: a git URL given as a scan target never prints or stores its
    credentials (userinfo, query, fragment); scheme, host and path stay."""

    URL = "https://user:" + CANARY + "@git.example.invalid/acme/tool.git?ref=" + CANARY + "#" + CANARY
    CLEAN = "https://git.example.invalid/acme/tool.git"

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        fake_home(self)
        self.lockfile = str(self.root / "lock.json")

    def outputs(self, argv: list[str], git: FakeGit) -> tuple[int, str]:
        """Exit code, and stdout plus stderr with debug lines on."""
        out, err = io.StringIO(), io.StringIO()
        with mock.patch("frisk.sources.subprocess.run", git), mock.patch.dict(os.environ, {"FRISK_DEBUG": "1"}), \
                mock.patch("frisk.report._USE_COLOR", False), contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(err):
            code = main(argv)
        return code, out.getvalue() + err.getvalue()

    def test_the_forms(self) -> None:
        for target, shown in (
            (self.URL, self.CLEAN),
            ("https://" + CANARY + "@git.example.invalid:8443/acme/tool.git", "https://git.example.invalid:8443/acme/tool.git"),
            ("ssh://git@git.example.invalid/acme/tool.git", "ssh://git@git.example.invalid/acme/tool.git"),
            ("ssh://git:" + CANARY + "@git.example.invalid/acme/tool.git", "ssh://git@git.example.invalid/acme/tool.git"),
            ("git@git.example.invalid:acme/tool.git", "git@git.example.invalid:acme/tool.git"),
            ("git:" + CANARY + "@git.example.invalid:acme/tool.git", "git@git.example.invalid:acme/tool.git"),
            ("github.com/acme/tool", "github.com/acme/tool"),
            ("./skills/tool", "./skills/tool"),
            ("https://user:" + CANARY + "#x@git.example.invalid/acme/tool.git", "<unparsable URL>"),
        ):
            with self.subTest(target=target.replace(CANARY, "<canary>")):
                self.assertEqual(display_target(target), shown)

    def test_no_output_format_or_debug_line_shows_the_token(self) -> None:
        git = FakeGit()
        for flags in ([], ["--json"], ["--sarif"], ["-q"]):
            with self.subTest(flags=flags):
                code, out = self.outputs([*flags, self.URL], git)
                self.assertEqual(code, 0)
                self.assertNotIn(CANARY, out)
        self.assertIn(f"verdict:   PASS    0 blocking · 0 warnings · 0 total  ({self.CLEAN})",
                      self.outputs([self.URL], git)[1])
        with mock.patch("frisk.sources.subprocess.run", git):
            self.assertEqual(json.loads(run(["--json", self.URL]))["target"], self.CLEAN)
        self.assertEqual(set(git.urls), {self.URL})  # a scan clones the URL as given, credential and all

    def test_the_lockfile_never_stores_the_token(self) -> None:
        git = FakeGit()
        code, out = self.outputs(["lock", self.URL, "--lockfile", self.lockfile], git)
        self.assertEqual(code, 0)
        data = Path(self.lockfile).read_bytes()
        self.assertNotIn(CANARY.encode(), data)
        lock = json.loads(data)
        self.assertEqual(list(lock["entries"]), [self.CLEAN])
        self.assertEqual(lock["entries"][self.CLEAN]["recompute"]["value"], self.CLEAN)
        for flags in (["verify"], ["verify", "--json"]):
            with self.subTest(flags=flags):
                code, out = self.outputs([*flags, "--lockfile", self.lockfile], git)
                self.assertEqual(code, 0)
                self.assertNotIn(CANARY, out)
        self.assertEqual(git.urls[-1], self.CLEAN)  # verify re-clones the clean URL; git's helper supplies auth

    def test_two_repositories_differing_by_path_stay_apart(self) -> None:
        a = "https://" + CANARY + "@git.example.invalid/acme/a.git"
        b = "https://" + CANARY + "@git.example.invalid/acme/b.git"
        git = FakeGit()
        self.assertEqual(self.outputs(["lock", a, b, "--lockfile", self.lockfile], git)[0], 0)
        self.assertEqual(list(pin.read_lock(self.lockfile)["entries"]),
                         ["https://git.example.invalid/acme/a.git", "https://git.example.invalid/acme/b.git"])
        code, out = self.outputs(["verify", "--lockfile", self.lockfile], git)
        self.assertIn("  [ok   ] https://git.example.invalid/acme/a.git\n", out)
        self.assertIn("  [ok   ] https://git.example.invalid/acme/b.git\n", out)

    def test_an_older_lock_with_a_credentialed_url_still_verifies(self) -> None:
        clone = self.root / "clone"
        clone.mkdir()
        (clone / "SKILL.md").write_text("hello\n", encoding="utf-8")
        old = {"version": 1, "entries": {self.URL: {**pin.fingerprint_path(clone), "kind": "source",
                                                    "recompute": {"type": "target", "value": self.URL}}}}
        pin.write_lock(old, self.lockfile)
        git = FakeGit()
        code, out = self.outputs(["verify", "--lockfile", self.lockfile], git)
        self.assertEqual(code, 0)
        self.assertIn(f"  [ok   ] {self.CLEAN}\n", out)
        self.assertNotIn(CANARY, out + self.outputs(["verify", "--json", "--lockfile", self.lockfile], git)[1])
        self.assertEqual(git.urls[-1], self.URL)  # the stored URL is what gets cloned, so it keeps working
        self.assertEqual(self.outputs(["lock", self.URL, "--lockfile", self.lockfile], git)[0], 0)
        self.assertNotIn(CANARY.encode(), Path(self.lockfile).read_bytes())  # the next lock rewrites it clean

    def test_a_failed_clone_never_echoes_the_token(self) -> None:
        git = FakeGit(fail=True)
        code, out = self.outputs([self.URL], git)
        self.assertEqual(code, 2)
        self.assertIn("frisk: git clone failed with exit code 128", out)
        self.assertNotIn(CANARY, out)
        pin.write_lock({"version": 1, "entries": {self.URL: {"digest": "x", "files": {}, "kind": "source",
                                                             "recompute": {"type": "target", "value": self.URL}}}},
                       self.lockfile)
        for flags in (["verify"], ["verify", "--json"]):
            with self.subTest(flags=flags):
                code, out = self.outputs([*flags, "--lockfile", self.lockfile], git)
                self.assertEqual(code, 1)
                self.assertNotIn(CANARY, out)

    def test_an_unrecognised_target_error_never_echoes_the_password(self) -> None:
        for target in ("git:" + CANARY + "@git.example.invalid:acme/tool.git",
                       "ftp://u:" + CANARY + "@h.example.invalid/x"):
            with self.subTest(target=target.replace(CANARY, "<canary>")):
                code, out = self.outputs([target], FakeGit())
                self.assertEqual(code, 2)
                self.assertIn("not a path or recognizable git URL", out)
                self.assertNotIn(CANARY, out)

    def test_a_url_frisk_cannot_split_is_not_pinned(self) -> None:
        code, out = self.outputs(["lock", "https://user:" + CANARY + "#x@git.example.invalid/r.git",
                                  "--lockfile", self.lockfile], FakeGit())
        self.assertEqual(code, 2)
        self.assertNotIn(CANARY, out)
        self.assertFalse(Path(self.lockfile).exists())

    def test_frisk_mcp_reports_the_clean_source(self) -> None:
        from frisk.mcp_server import handle
        for git in (FakeGit(), FakeGit(fail=True)):
            with self.subTest(fail=git.fail), mock.patch("frisk.sources.subprocess.run", git):
                resp = handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                               "params": {"name": "scan_artifact", "arguments": {"source": self.URL}}})
                text = resp["result"]["content"][0]["text"] if resp else ""
                self.assertNotIn(CANARY, text)
                if not git.fail:
                    self.assertEqual(json.loads(text)["source"], self.CLEAN)


if __name__ == "__main__":
    unittest.main()
