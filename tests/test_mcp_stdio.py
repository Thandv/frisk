"""FR-E5 t3: frisk-mcp answers every malformed request with a JSON-RPC error and keeps serving.

Drives `python -m frisk.mcp_server` over stdio. On main, '[1]' (or a non-string method, or
list params) ended the server with a traceback, a line that was not JSON got no reply, one
byte that is not UTF-8 ended the server under a UTF-8 locale, ping was 'method not found'
and the protocol version was always 2024-11-05.
(Named test_mcp_stdio.py, not the ask's test_mcp_server.py: FR-E1's characterization file is
test_mcp_server_characterization.py, and this keeps the new stdio cases in a file of their own.)
Run: PYTHONPATH=src python3 -B -m unittest discover -s tests
"""
from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from frisk import mcp_server

REPO = Path(__file__).resolve().parent.parent
TIMEOUT_S = 30  # a hang guard: the whole conversation takes well under a second
PING = {"jsonrpc": "2.0", "id": "after", "method": "ping"}
TOOLS_LIST = {"jsonrpc": "2.0", "id": "list", "method": "tools/list"}


def call(rid: object, params: object) -> dict:
    return {"jsonrpc": "2.0", "id": rid, "method": "tools/call", "params": params}


def error(rid: object, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}


# (label, the malformed line as bytes, the reply it gets); each is followed by a ping.
MALFORMED: list[tuple[str, bytes, dict]] = [
    ("a list", b"[1]", error(None, -32600, "invalid request: not a JSON object")),
    ("not JSON", b"{not json", error(None, -32700, "parse error")),
    ("not UTF-8", b'{"jsonrpc": "2.0", "id": 1, "method": "ping", "x": "\xff"}', error(None, -32700, "parse error")),
    ("nested too deep", b"[" * 100_000, error(None, -32700, "parse error")),
    ("a number", b"5", error(None, -32600, "invalid request: not a JSON object")),
    ("null", b"null", error(None, -32600, "invalid request: not a JSON object")),
    ("method not a string", json.dumps({"jsonrpc": "2.0", "id": 3, "method": 5}).encode(),
     error(3, -32600, "invalid request: method is not a string")),
    ("no method", json.dumps({"jsonrpc": "2.0", "id": 4}).encode(),
     error(4, -32600, "invalid request: method is not a string")),
    ("list params", json.dumps(call(5, [1])).encode(), error(5, -32600, "invalid request: params is not an object")),
    ("null params", json.dumps(call(6, None)).encode(), error(6, -32600, "invalid request: params is not an object")),
    ("list arguments", json.dumps(call(7, {"name": "scan_text", "arguments": [1]})).encode(),
     error(7, -32600, "invalid request: arguments is not an object")),
    ("unknown tool", json.dumps(call(8, {"name": "nope", "arguments": {}})).encode(),
     error(8, -32602, "unknown tool: 'nope'")),
    ("unhashable tool name", json.dumps(call(9, {"name": ["scan_text"], "arguments": {}})).encode(),
     error(9, -32602, "unknown tool: ['scan_text']")),
    ("unknown method", json.dumps({"jsonrpc": "2.0", "id": 10, "method": "bogus/x"}).encode(),
     error(10, -32601, "method not found: bogus/x")),
]


def converse(lines: list[bytes]) -> list[dict]:
    """Run frisk-mcp on these input lines (stdin decoded as strict UTF-8, as under a UTF-8
    locale) and return its replies, in order."""
    with tempfile.TemporaryDirectory() as home:
        env = {k: v for k, v in os.environ.items() if not k.startswith("FRISK_")}
        env.update(PYTHONPATH=str(REPO / "src"), HOME=home, PYTHONIOENCODING="utf-8:strict")
        proc = subprocess.run([sys.executable, "-m", "frisk.mcp_server"], input=b"".join(x + b"\n" for x in lines),
                              capture_output=True, env=env, timeout=TIMEOUT_S, cwd=home)
    if proc.returncode != 0 or proc.stderr:
        raise AssertionError(f"frisk-mcp failed ({proc.returncode}): {proc.stderr.decode(errors='replace')[-500:]}")
    return [json.loads(line) for line in proc.stdout.decode().splitlines()]


class TestStdio(unittest.TestCase):
    def test_a_list_then_tools_list_gives_two_replies(self) -> None:
        first, second = converse([b"[1]", json.dumps(TOOLS_LIST).encode()])
        self.assertEqual(first, error(None, -32600, "invalid request: not a JSON object"))
        self.assertEqual(second["id"], "list")
        self.assertEqual([t["name"] for t in second["result"]["tools"]],
                         ["scan_text", "scan_artifact", "vet_mcp_server"])

    def test_each_malformed_request_gets_an_error_and_the_next_is_answered(self) -> None:
        lines: list[bytes] = []
        for _label, line, _reply in MALFORMED:
            lines += [line, json.dumps(PING).encode()]
        replies = converse(lines)
        self.assertEqual(len(replies), 2 * len(MALFORMED))
        for (label, _line, reply), (got, after) in zip(MALFORMED, zip(replies[::2], replies[1::2])):
            with self.subTest(label):
                self.assertEqual(got, reply)
                self.assertEqual(after, {"jsonrpc": "2.0", "id": "after", "result": {}})

    def test_a_tool_that_cannot_do_its_job_answers_with_is_error(self) -> None:
        missing, scanned = converse([
            json.dumps(call(1, {"name": "scan_text", "arguments": {}})).encode(),
            json.dumps(call(2, {"name": "scan_text", "arguments": {"text": "hello"}})).encode()])
        self.assertIs(missing["result"]["isError"], True)
        self.assertEqual(json.loads(scanned["result"]["content"][0]["text"])["verdict"], "PASS")

    def test_protocol_version_is_negotiated(self) -> None:
        asked: list[object] = ["2024-11-05", "2025-03-26", "2025-06-18", "1999-01-01", 5, None]
        replies = converse([json.dumps({"jsonrpc": "2.0", "id": i, "method": "initialize",
                                        "params": {"protocolVersion": v, "capabilities": {}}}).encode()
                            for i, v in enumerate(asked)])
        self.assertEqual([r["result"]["protocolVersion"] for r in replies],
                         ["2024-11-05", "2025-03-26", "2025-06-18", "2025-06-18", "2025-06-18", "2025-06-18"])
        self.assertEqual({r["result"]["serverInfo"]["name"] for r in replies}, {"frisk"})


class TestInternalErrors(unittest.TestCase):
    """A fault in frisk itself answers that request with -32603; the loop keeps serving."""

    def run_main(self, requests: list[dict]) -> list[dict]:
        out = io.StringIO()
        with mock.patch("sys.stdin", io.StringIO("".join(json.dumps(r) + "\n" for r in requests))), \
                mock.patch("sys.stdout", out):
            mcp_server.main()
        return [json.loads(line) for line in out.getvalue().splitlines()]

    def test_scan_text_raising_answers_minus_32603_and_tools_list_still_works(self) -> None:
        with mock.patch("frisk.mcp_server.scan_text", side_effect=Exception("boom")):
            failed, listed = self.run_main([call(1, {"name": "scan_text", "arguments": {"text": "x"}}), TOOLS_LIST])
        self.assertEqual(failed, error(1, -32603, "internal error (Exception)"))
        self.assertEqual(len(listed["result"]["tools"]), 3)

    def test_handle_raising_answers_minus_32603_with_the_request_id(self) -> None:
        with mock.patch("frisk.mcp_server._tools_list", side_effect=KeyError("bug")):
            failed, pinged = self.run_main([TOOLS_LIST, PING])
        self.assertEqual(failed, error("list", -32603, "internal error (KeyError)"))
        self.assertEqual(pinged["result"], {})


if __name__ == "__main__":
    unittest.main()
