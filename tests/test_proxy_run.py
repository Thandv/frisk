"""Characterization test for Proxy.run end to end: `frisk proxy -- <fake server>` as a subprocess.

Pins TODAY's relay behaviour: the poisoned tool is dropped, the clean one passes, and
both the proxy and the fake server it spawned have exited once the client closes stdin.
Run: PYTHONPATH=src python3 -m unittest discover -s tests
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FAKE_SERVER = REPO / "tests" / "fixtures" / "fake_mcp_server.py"
TIMEOUT_S = 5


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


class TestProxyRun(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.pidfile = Path(tmp.name) / "fake.pid"

    def _server_pid(self) -> int | None:
        try:
            return int(self.pidfile.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def _reap(self, proc: subprocess.Popen[str]) -> None:
        """Cleanup: never leave the proxy or the fake server running."""
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=TIMEOUT_S)
        pid = self._server_pid()
        if pid is not None and _alive(pid):
            os.kill(pid, signal.SIGKILL)

    def test_relay_drops_poisoned_tool_and_exits(self) -> None:
        # pytest's `pythonpath` setting only affects this process, so the child gets
        # PYTHONPATH explicitly.
        env = {**os.environ, "PYTHONPATH": str(REPO / "src"), "FAKE_MCP_PIDFILE": str(self.pidfile)}
        proc = subprocess.Popen(
            [sys.executable, "-m", "frisk.cli", "proxy", "--", sys.executable, str(FAKE_SERVER)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, env=env, cwd=str(REPO),
        )
        self.addCleanup(self._reap, proc)
        requests = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        ]
        stdin = "".join(json.dumps(r) + "\n" for r in requests)

        # communicate() closes stdin after writing; the proxy forwards EOF, the fake
        # server exits, and the proxy returns its exit code.
        out, err = proc.communicate(stdin, timeout=TIMEOUT_S)

        self.assertIsNotNone(proc.poll())
        self.assertEqual(proc.returncode, 0, err)
        responses = [json.loads(line) for line in out.splitlines()]
        self.assertEqual([r["id"] for r in responses], [1, 2])
        self.assertEqual(responses[0]["result"]["serverInfo"], {"name": "fake-mcp", "version": "0"})
        names = [t["name"] for t in responses[1]["result"]["tools"]]
        self.assertEqual(names, ["echo-text"])
        self.assertEqual(responses[1]["result"]["tools"][0]["description"], "Return the given text unchanged.")
        self.assertIn("[frisk-proxy] BLOCKED tool 'save-note'", err)
        self.assertIn("[frisk-proxy] server exited (0); dropped=1 flagged=0", err)

        server_pid = self._server_pid()
        if server_pid is None:
            self.fail("fake MCP server never started (no pidfile)")
        # Proxy.run waits on the server before returning, so it is already reaped.
        self.assertFalse(_alive(server_pid), "fake MCP server outlived the proxy")


if __name__ == "__main__":
    unittest.main()
