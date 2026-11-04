"""FR-E5 t2: `frisk proxy` end to end with a misbehaving fake server (tests/fixtures/fake_mcp_server.py).

A line that is not UTF-8 no longer kills the relay; the server is stopped and reaped on every
way the proxy ends (its input closing, SIGTERM, SIGINT, its output closing); a server that
cannot be launched or a --log that cannot be opened is one line and exit 2; a 5 MB tool result
is delivered, marked partially scanned. No sleeps: each wait is on a pipe or a process, under a
deadline that kills the proxy if it hangs.
Run: PYTHONPATH=src python3 -B -m unittest discover -s tests
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import signal
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from typing import IO
from unittest import mock

from frisk import proxy

REPO = Path(__file__).resolve().parent.parent
FAKE_SERVER = REPO / "tests" / "fixtures" / "fake_mcp_server.py"
DEADLINE_S = 10  # a hang guard per test; each finishes in about a second
INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
LIST = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
BIG = {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "big", "arguments": {}}}


def gone(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    return False


class ProxyCase(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.pidfile = self.tmp / "server.pid"

    def start(self, *proxy_args: str, linger: bool = False) -> subprocess.Popen[bytes]:
        env = {**os.environ, "PYTHONPATH": str(REPO / "src"), "FAKE_MCP_PIDFILE": str(self.pidfile),
               "FAKE_MCP_EXTRAS": "1", "FAKE_MCP_LINGER": "1" if linger else "0", "FRISK_DEBUG": "0",
               "HOME": str(self.tmp), "XDG_STATE_HOME": str(self.tmp)}  # FR-E6: pins never in the real state dir
        argv = proxy_args or ("--", sys.executable, str(FAKE_SERVER))
        proc = subprocess.Popen([sys.executable, "-m", "frisk.cli", "proxy", *argv], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, cwd=str(self.tmp))
        guard = threading.Timer(DEADLINE_S, proc.kill)  # a hung proxy fails the test, never hangs it
        guard.start()
        self.addCleanup(guard.cancel)
        self.addCleanup(self.reap, proc)
        return proc

    def reap(self, proc: subprocess.Popen[bytes]) -> None:
        if proc.poll() is None:
            proc.kill()
        proc.wait()
        for pipe in (proc.stdin, proc.stdout, proc.stderr):
            if pipe is not None:
                with contextlib.suppress(BrokenPipeError):  # unread input of a proxy that is gone
                    pipe.close()
        if self.pidfile.exists() and not gone(self.server_pid()):
            os.kill(self.server_pid(), signal.SIGKILL)

    def server_pid(self) -> int:
        return int(self.pidfile.read_text(encoding="utf-8"))

    @staticmethod
    def send(proc: subprocess.Popen[bytes], *msgs: dict) -> None:
        assert proc.stdin is not None
        proc.stdin.write(b"".join(json.dumps(m).encode() + b"\n" for m in msgs))
        proc.stdin.flush()

    @staticmethod
    def reply(stream: IO[bytes] | None) -> dict:
        assert stream is not None
        line = stream.readline()
        if not line:
            raise AssertionError("the proxy closed its output (or was killed by the deadline)")
        return json.loads(line)


class TestRelay(ProxyCase):
    def test_a_line_that_is_not_utf8_is_dropped_and_tools_list_still_relayed(self) -> None:
        proc = self.start()
        self.send(proc, INIT, LIST)
        self.assertEqual(self.reply(proc.stdout)["id"], 1)
        listed = self.reply(proc.stdout)
        self.assertEqual([t["name"] for t in listed["result"]["tools"]], ["echo-text", "météo"])
        # Non-ASCII text round-trips: the client reads the description the server sent.
        self.assertEqual(listed["result"]["tools"][1]["description"], "Prévisions météo — 東京 et Zürich, ±2 °C.")
        out, err = proc.communicate(b"")
        self.assertEqual((proc.returncode, out), (0, b""))
        self.assertIn(b"dropped a server line that is not JSON (18 characters)", err)

    def test_a_5_mb_result_is_delivered_and_marked_partially_scanned(self) -> None:
        proc = self.start()
        self.send(proc, BIG)
        reply = self.reply(proc.stdout)
        text = reply["result"]["content"][0]["text"]
        self.assertTrue(text.startswith("[frisk: partially scanned"), text[:80])
        self.assertIn("[frisk: possible prompt-injection", text[:400])  # the directive at the end was found
        self.assertGreater(len(text), 5_000_000)
        proc.communicate(b"")
        self.assertEqual(proc.returncode, 0)


class TestLifecycle(ProxyCase):
    def started(self, linger: bool = False) -> subprocess.Popen[bytes]:
        proc = self.start(linger=linger)
        self.send(proc, INIT)
        self.assertEqual(self.reply(proc.stdout)["id"], 1)  # the server is up and its pid written
        return proc

    def test_closing_the_client_input_ends_proxy_and_server(self) -> None:
        proc = self.started()
        proc.communicate(b"", timeout=6)
        self.assertEqual(proc.returncode, 0)
        self.assertTrue(gone(self.server_pid()))

    def test_sigterm_and_sigint_leave_no_server(self) -> None:
        for sig in (signal.SIGTERM, signal.SIGINT):
            with self.subTest(signal=sig.name):
                proc = self.started(linger=True)  # the server outlives a proxy that does not stop it
                proc.send_signal(sig)
                _, err = proc.communicate(timeout=DEADLINE_S)
                self.assertEqual(proc.returncode, 128 + signal.SIGTERM, err)  # the server's status: stopped by SIGTERM
                self.assertIn(b"stopped by a signal", err)
                self.assertTrue(gone(self.server_pid()))

    def test_a_client_that_stops_reading_ends_proxy_and_server(self) -> None:
        proc = self.started(linger=True)
        assert proc.stdout is not None
        proc.stdout.close()
        self.send(proc, BIG)  # its 5 MB reply hits the closed pipe
        assert proc.stdin is not None
        proc.stdin.close()
        self.assertEqual(proc.wait(timeout=DEADLINE_S), 128 + signal.SIGTERM)  # the proxy stopped the server
        assert proc.stderr is not None
        self.assertIn(b"client gone", proc.stderr.read())
        self.assertTrue(gone(self.server_pid()))


class TestServerIgnoringEndOfInput(ProxyCase):
    def test_the_proxy_stops_a_server_that_outlives_its_input(self) -> None:
        # In process, with the grace period cut short (frisk waits STOP_GRACE_S = 5 s).
        env = {"FAKE_MCP_PIDFILE": str(self.pidfile), "FAKE_MCP_LINGER": "1"}
        log = io.StringIO()
        with mock.patch.dict(os.environ, env), mock.patch.object(proxy, "STOP_GRACE_S", 0.3), \
                mock.patch("sys.stdin", io.StringIO("")), mock.patch("sys.stdout", io.StringIO()):
            status = proxy.Proxy([sys.executable, str(FAKE_SERVER)], log=log).run()
        self.assertEqual(status, 128 + signal.SIGTERM)
        self.assertIn("client input ended and the server did not exit; stopping it", log.getvalue())
        self.assertTrue(gone(self.server_pid()))


class TestCannotStart(ProxyCase):
    def test_a_server_command_that_is_not_executable_exits_2_with_one_line(self) -> None:
        script = self.tmp / "server.sh"
        script.write_text("#!/bin/sh\n", encoding="utf-8")
        script.chmod(0o644)
        log = self.tmp / "proxy.log"  # proxy events go here, so stderr holds only the error
        proc = self.start("--log", str(log), "--", str(script))
        out, err = proc.communicate(b"")
        self.assertEqual((proc.returncode, out), (2, b""))
        self.assertEqual(err.decode().splitlines(),
                         [f"frisk proxy: cannot launch server: [Errno 13] Permission denied: '{script}'"])
        self.assertEqual(log.read_text(encoding="utf-8"), f"[frisk-proxy] started; wrapping: {script}\n")

    def test_a_log_file_that_cannot_be_opened_exits_2_with_one_line(self) -> None:
        proc = self.start("--log", str(self.tmp), "--", sys.executable, str(FAKE_SERVER))
        out, err = proc.communicate(b"")
        self.assertEqual((proc.returncode, out), (2, b""))
        lines = err.decode().splitlines()
        self.assertEqual(len(lines), 1, err)
        self.assertTrue(lines[0].startswith("frisk proxy: cannot open the log file: [Errno 21] Is a directory"),
                        lines)
        self.assertFalse(self.pidfile.exists())  # no server was started


if __name__ == "__main__":
    unittest.main()
