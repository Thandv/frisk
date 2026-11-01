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
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from frisk import report
from frisk.cli import main
from frisk.engine import ScanResult
from frisk.report import AuditRecord, audit_text
from frisk.sources import ServerRef, display_ref

CANARY = "c4n" + "ary-" + "51f0" + "e2d7"


def run(argv: list[str]) -> str:
    out = io.StringIO()
    with mock.patch("frisk.report._USE_COLOR", False), contextlib.redirect_stdout(out):
        main(argv)
    return out.getvalue()


def ref(kind: str, value: str) -> ServerRef:
    return ServerRef("s", kind, value, False)


class DisplayRefTest(unittest.TestCase):
    def test_url_keeps_scheme_host_port_and_path(self) -> None:
        url = "https://user:" + CANARY + "@h.example.invalid:8443/a/b;p?token=" + CANARY + "#" + CANARY
        self.assertEqual(display_ref(ref("remote", url)), "https://h.example.invalid:8443/a/b;p")

    def test_plain_url_is_unchanged(self) -> None:
        self.assertEqual(display_ref(ref("remote", "https://mcp.example.invalid/sse")),
                         "https://mcp.example.invalid/sse")

    def test_unparsable_remote_ref_is_not_shown(self) -> None:
        for value in ("http://[::1/sse?token=" + CANARY, "mcp.example.invalid/sse?token=" + CANARY,
                      "https:///path?token=" + CANARY, ""):
            with self.subTest(n=len(value)):
                self.assertEqual(display_ref(ref("remote", value)), "<unparsable URL>")

    def test_a_package_given_as_a_url_is_redacted_too(self) -> None:
        spec = "https://u:" + CANARY + "@registry.example.invalid/pkg.tgz?sig=" + CANARY
        self.assertEqual(display_ref(ref("package", spec)), "https://registry.example.invalid/pkg.tgz")

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
        for shown in ("https://q.example.invalid/sse", "https://u.example.invalid/mcp", "https://f.example.invalid/mcp",
                      "https://h.example.invalid/mcp", "/nonexistent.invalid/bin/srv", "https://r.example.invalid/p.tgz"):
            with self.subTest(shown=shown):
                self.assertIn("→ " + shown + "\n", out)

    def test_json_output_has_no_canary(self) -> None:
        out = run(["--json", "--mcp-config", str(self.cfg)])
        json.loads(out)
        self.assertNotIn(CANARY, out)


if __name__ == "__main__":
    unittest.main()
