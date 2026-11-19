"""FR-E5 t2: `frisk proxy` end to end with a misbehaving fake server (tests/fixtures/fake_mcp_server.py).

A line that is not UTF-8 no longer kills the relay; the server is stopped and reaped on every
way the proxy ends (its input closing, SIGTERM, SIGINT, its output closing); a server that
cannot be launched or a --log that cannot be opened is one line and exit 2; a 5 MB tool result
is delivered, marked partially scanned. Each wait is on a pipe or a process, under a deadline
that kills the proxy if it hangs; the only sleeps are the slow-reader stalls, which outlast the
proxy's STOP_GRACE_S bound on purpose, and a late reader's 2 s stall.
Run: PYTHONPATH=src python3 -B -m unittest discover -s tests
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import resource
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import IO
from unittest import mock

from frisk import proxy

REPO = Path(__file__).resolve().parent.parent
FAKE_SERVER = REPO / "tests" / "fixtures" / "fake_mcp_server.py"
DEADLINE_S = 60  # a hang guard per test (scanning a 5 MB reply is slow on a loaded machine)
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
        self.grandchild_file = self.tmp / "grandchild.pid"

    def start(self, *proxy_args: str, linger: bool = False,
              server_env: dict[str, str] | None = None, pass_fds: tuple[int, ...] = (),
              stdout: int = subprocess.PIPE) -> subprocess.Popen[bytes]:
        env = {**os.environ, "PYTHONPATH": str(REPO / "src"), "FAKE_MCP_PIDFILE": str(self.pidfile),
               "FAKE_MCP_EXTRAS": "1", "FAKE_MCP_LINGER": "1" if linger else "0", "FRISK_DEBUG": "0",
               "HOME": str(self.tmp), "XDG_STATE_HOME": str(self.tmp),  # pins never in the real state dir
               **(server_env or {})}
        argv = proxy_args or ("--", sys.executable, str(FAKE_SERVER))
        proc = subprocess.Popen([sys.executable, "-m", "frisk.cli", "proxy", *argv], stdin=subprocess.PIPE,
                                stdout=stdout, stderr=subprocess.PIPE, env=env, cwd=str(self.tmp),
                                pass_fds=pass_fds)
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
        if self.grandchild_file.exists() and not gone(self.grandchild_pid()):
            os.kill(self.grandchild_pid(), signal.SIGKILL)

    def server_pid(self) -> int:
        return int(self.pidfile.read_text(encoding="utf-8"))

    def grandchild_pid(self) -> int:
        return int(self.grandchild_file.read_text(encoding="utf-8"))

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
    def started(self, linger: bool = False, server_env: dict[str, str] | None = None) -> subprocess.Popen[bytes]:
        proc = self.start(linger=linger, server_env=server_env)
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

    def test_a_client_that_closes_only_its_output_ends_proxy_and_server(self) -> None:
        proc = self.started()
        assert proc.stdout is not None
        proc.stdout.close()  # stdin stays open: the server never sees end of input from the client
        self.send(proc, LIST)  # a small reply hits the closed pipe
        t0 = time.monotonic()
        status = proc.wait(timeout=DEADLINE_S)
        self.assertLess(time.monotonic() - t0, 10)
        self.assertEqual(status, 0)  # the server's status, never the 120 of a failed flush at exit
        assert proc.stderr is not None
        self.assertIn(b"client gone", proc.stderr.read())
        self.assertTrue(gone(self.server_pid()))

    def test_the_proxy_stops_relaying_when_a_grandchild_holds_the_server_output(self) -> None:
        proc = self.started(server_env={"FAKE_MCP_GRANDCHILD": str(self.grandchild_file)})
        assert proc.stdin is not None
        proc.stdin.close()  # the server exits; its sleeping child still holds the pipe to the proxy
        t0 = time.monotonic()
        status = proc.wait(timeout=DEADLINE_S)
        self.assertLess(time.monotonic() - t0, proxy.STOP_GRACE_S + 5)
        self.assertEqual(status, 0)
        self.assertTrue(gone(self.server_pid()))
        self.assertFalse(gone(self.grandchild_pid()))  # it did hold the pipe the whole time

    def test_a_reply_in_flight_when_the_client_closes_its_input_is_still_delivered(self) -> None:
        proc = self.start(server_env={"FAKE_MCP_REPLY_DELAY_S": str(proxy.STOP_GRACE_S / 2)})
        self.send(proc, INIT)
        assert proc.stdin is not None
        proc.stdin.close()  # the reply comes after half the grace period, with input already at its end
        self.assertEqual(self.reply(proc.stdout)["id"], 1)
        self.assertEqual(proc.wait(timeout=DEADLINE_S), 0)

    def test_a_slow_reader_still_gets_the_whole_large_reply_after_its_input_closed(self) -> None:
        proc = self.start()
        self.send(proc, INIT, BIG)
        assert proc.stdin is not None
        proc.stdin.close()  # the server replies, then exits on end of input, while the client is not reading
        time.sleep(proxy.STOP_GRACE_S + 2)  # a slow reader: longer than the proxy's bound
        self.assertEqual(self.reply(proc.stdout)["id"], 1)
        text = self.reply(proc.stdout)["result"]["content"][0]["text"]
        self.assertGreater(len(text), 5_000_000)
        self.assertEqual(proc.wait(timeout=DEADLINE_S), 0)

    def test_replies_queued_behind_a_slow_reader_are_all_delivered_after_its_input_closed(self) -> None:
        proc = self.start()
        self.send(proc, INIT, BIG, LIST)
        assert proc.stdin is not None
        proc.stdin.close()  # the server writes all three replies and exits; the client is not reading
        time.sleep(proxy.STOP_GRACE_S + 2)  # longer than the proxy's bound after the server exits
        ids = [self.reply(proc.stdout)["id"] for _ in range(3)]
        self.assertEqual(ids, [1, 3, 2])
        self.assertEqual(proc.wait(timeout=DEADLINE_S), 0)

    def test_pipelined_replies_written_before_the_server_exited_all_arrive_to_a_slow_reader(self) -> None:
        proc = self.start()
        count = 200  # about 0.7 KB each: more than the client's pipe holds (the relay blocks writing), less than
        #              the pipes and the relay's buffer hold together (the server still writes it all and exits)
        self.send(proc, *({**LIST, "id": 100 + n} for n in range(count)))
        assert proc.stdin is not None and proc.stdout is not None
        proc.stdin.close()  # the server answers every request and exits on end of input
        data = os.read(proc.stdout.fileno(), 8192)  # one chunk, then the client stalls
        time.sleep(proxy.STOP_GRACE_S + 2)  # longer than the bound; the replies are all still queued
        data += proc.stdout.read()
        ids = [json.loads(line)["id"] for line in data.splitlines()]
        self.assertEqual(ids, list(range(100, 100 + count)))
        self.assertEqual(proc.wait(timeout=DEADLINE_S), 0)

    def test_sigterm_while_a_large_reply_is_relayed_exits_143(self) -> None:
        proc = self.started()
        self.send(proc, BIG)
        assert proc.stdout is not None and proc.stderr is not None
        self.assertEqual(len(proc.stdout.read(1000)), 1000)  # the proxy is mid-write; the client stops reading
        proc.send_signal(signal.SIGTERM)
        self.assertEqual(proc.wait(timeout=DEADLINE_S), 143)
        self.assertNotIn(b"Fatal Python error", proc.stderr.read())
        self.assertTrue(gone(self.server_pid()))

    def test_the_proxy_stops_relaying_a_grandchild_that_keeps_writing_and_cuts_no_line(self) -> None:
        proc = self.started(server_env={"FAKE_MCP_GRANDCHILD": str(self.grandchild_file),
                                        "FAKE_MCP_GRANDCHILD_LINES": "1"})
        assert proc.stdin is not None and proc.stdout is not None and proc.stderr is not None
        lines: list[bytes] = []
        stdout = proc.stdout
        reader = threading.Thread(target=lambda: lines.extend(stdout), daemon=True)
        reader.start()
        proc.stdin.close()  # the server exits; its child then writes large lines without end
        t0 = time.monotonic()
        status = proc.wait(timeout=DEADLINE_S)
        self.assertLess(time.monotonic() - t0, proxy.STOP_GRACE_S + 5)
        reader.join(DEADLINE_S)
        self.assertEqual(status, 0)
        self.assertNotIn(b"Fatal Python error", proc.stderr.read())
        self.assertGreater(len(lines), 0)  # the child's output was relayed
        for line in lines:  # every line that reached the client is whole
            self.assertEqual(json.loads(line)["method"], "notifications/message")

    def test_a_line_being_written_when_relaying_stops_is_finished_for_a_stalled_reader(self) -> None:
        proc = self.started(server_env={"FAKE_MCP_GRANDCHILD": str(self.grandchild_file),
                                        "FAKE_MCP_GRANDCHILD_LINES": "1"})
        assert proc.stdin is not None and proc.stdout is not None
        proc.stdin.close()  # the server exits; its child's first large line fills the pipe to the client
        time.sleep(proxy.STOP_GRACE_S + 2)  # the client stalls past the bound, the proxy mid-line
        lines = proc.stdout.read().splitlines()
        self.assertEqual(proc.wait(timeout=DEADLINE_S), 0)
        self.assertGreater(len(lines), 0)
        for line in lines:  # the line being written when relaying stopped arrives whole
            self.assertEqual(json.loads(line)["method"], "notifications/message")


class TestNonBlockingClientOutput(ProxyCase):
    def test_a_client_output_left_non_blocking_gets_every_reply_whole(self) -> None:
        r, w = os.pipe()
        self.addCleanup(os.close, r)
        os.set_blocking(w, False)  # as a client may leave it: a full pipe is EAGAIN, not a client gone
        try:
            proc = self.start(stdout=w)
        finally:
            os.close(w)
        self.send(proc, INIT, BIG, LIST)
        assert proc.stdin is not None
        proc.stdin.close()
        time.sleep(2)  # the client reads late: the proxy's writes find the pipe full
        chunks = []
        while True:
            chunk = os.read(r, 1 << 20)
            if not chunk:
                break
            chunks.append(chunk)
        self.assertEqual(proc.wait(timeout=DEADLINE_S), 0)
        replies = [json.loads(line) for line in b"".join(chunks).splitlines()]
        self.assertEqual([reply["id"] for reply in replies], [1, 3, 2])
        self.assertGreater(len(replies[1]["result"]["content"][0]["text"]), 5_000_000)
        assert proc.stderr is not None
        self.assertNotIn(b"client gone", proc.stderr.read())


class TestManyDescriptors(ProxyCase):
    def test_replies_are_relayed_when_the_server_pipe_is_numbered_above_1024(self) -> None:
        # The proxy inherits about 1100 open descriptors, every number from 3 up, so the pipe it
        # opens to the server gets a number past 1024, which select.select cannot wait on.
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        wanted = 2048 if hard == resource.RLIM_INFINITY else min(hard, 2048)
        if wanted < 1200:
            self.skipTest(f"the descriptor limit ({hard}) is too low")
        if soft < wanted:
            resource.setrlimit(resource.RLIMIT_NOFILE, (wanted, hard))
            self.addCleanup(resource.setrlimit, resource.RLIMIT_NOFILE, (soft, hard))
        held = [os.open(os.devnull, os.O_RDONLY) for _ in range(1100)]
        self.addCleanup(lambda: [os.close(fd) for fd in held])
        self.assertGreater(max(held), 1024)
        passed = tuple(fd for fd in range(3, max(held) + 1) if self.is_open(fd))  # the parent's own too: no gaps
        self.assertEqual(len(passed), max(held) - 2)
        proc = self.start(pass_fds=passed)
        self.send(proc, INIT, LIST)
        out, err = proc.communicate(b"")  # input ends at once: a relay that failed leaves nothing
        self.assertEqual([json.loads(line)["id"] for line in out.splitlines()], [1, 2], err)
        self.assertEqual(proc.returncode, 0, err)

    @staticmethod
    def is_open(fd: int) -> bool:
        try:
            os.fstat(fd)
        except OSError:
            return False
        return True


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


class TestWithoutPosixOnlyModules(ProxyCase):
    """fcntl and termios do not exist on Windows; no frisk command may need them to start."""

    def test_the_cli_imports_and_its_help_runs_without_fcntl_and_termios(self) -> None:
        code = ("import sys; sys.modules['fcntl'] = None; sys.modules['termios'] = None\n"
                "from frisk import cli\n"
                "sys.exit(cli.main(['--help']))")
        done = subprocess.run([sys.executable, "-c", code], capture_output=True, timeout=DEADLINE_S,
                              env={**os.environ, "PYTHONPATH": str(REPO / "src")}, cwd=str(self.tmp))
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn(b"frisk proxy", done.stdout)

    def test_the_proxy_relays_and_exits_with_the_server_without_fcntl_and_termios(self) -> None:
        code = ("import sys; sys.modules['fcntl'] = None; sys.modules['termios'] = None\n"
                "from frisk import cli\n"
                "sys.exit(cli.main(sys.argv[1:]))")
        env = {**os.environ, "PYTHONPATH": str(REPO / "src"), "FAKE_MCP_PIDFILE": str(self.pidfile),
               "FRISK_DEBUG": "0", "HOME": str(self.tmp), "XDG_STATE_HOME": str(self.tmp)}
        done = subprocess.run([sys.executable, "-c", code, "proxy", "--", sys.executable, str(FAKE_SERVER)],
                              input=json.dumps(INIT).encode() + b"\n", capture_output=True, timeout=DEADLINE_S,
                              env=env, cwd=str(self.tmp))
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(json.loads(done.stdout)["id"], 1)
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
