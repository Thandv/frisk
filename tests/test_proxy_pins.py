"""FR-E6 F3.02: frisk proxy pins tools across runs, over the whole tool definition.

The pin is sha256 of the canonical JSON of name, title, description, inputSchema and
annotations, kept in ${XDG_STATE_HOME:-~/.local/state}/frisk/pins/<sha256 of the server
argv>.json (--pins FILE elsewhere, --no-pins: nowhere), written atomically with mode 0600.
The file holds hashes only. A second Proxy flags a changed definition (drops it with
--on-change drop); a corrupt pins file, a failed write or an unwritable directory is logged
once and the relay goes on with pins in memory. XDG_STATE_HOME and HOME are temp dirs here.
Run: PYTHONPATH=src python3 -B -m unittest discover -s tests
"""
from __future__ import annotations

import io
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from _home import fake_home
from frisk import cli, proxy
from frisk.proxy import Proxy, default_pins_file, tool_pin

SERVER = ["uvx", "acme-notes-server"]
SECRET_DESC = "Keep notes for the user, version one."


def tools_msg(*tools: dict) -> dict:
    return {"jsonrpc": "2.0", "id": 1, "result": {"tools": [dict(t) for t in tools]}}


def tool(description: str = SECRET_DESC, **extra: object) -> dict:
    return {"name": "notes", "description": description,
            "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}}, **extra}


class PinsCase(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.state = Path(tmp.name) / "state"
        fake_home(self, Path(tmp.name))
        patcher = mock.patch.dict(os.environ, {"XDG_STATE_HOME": str(self.state)})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.file = default_pins_file(SERVER)
        self.log = io.StringIO()

    def proxy(self, on_change: str = "flag", pins_file: Path | None = None) -> Proxy:
        return Proxy(SERVER, log=self.log, pins_file=pins_file or self.file, on_change=on_change)

    def listed(self, p: Proxy, *tools: dict) -> list[dict]:
        out = p.inspect(tools_msg(*tools))
        assert isinstance(out, dict)
        return out["result"]["tools"]


class TestPersistence(PinsCase):
    def test_the_default_file_is_under_xdg_state_home(self) -> None:
        self.assertEqual(self.file.parent, self.state / "frisk" / "pins")
        self.assertEqual(len(self.file.stem), 64)
        self.assertNotEqual(default_pins_file(SERVER + ["--x"]), self.file)
        with mock.patch.dict(os.environ, {"XDG_STATE_HOME": "relative/dir"}):  # ignored, as the spec says
            self.assertEqual(default_pins_file(SERVER).parent, Path.home() / ".local" / "state" / "frisk" / "pins")

    def test_a_second_instance_flags_a_changed_description(self) -> None:
        self.listed(self.proxy(), tool())
        (seen,) = self.listed(self.proxy(), tool("Keep notes for the user, version two."))
        self.assertIn("definition changed since it was pinned", seen["description"])

    def test_with_on_change_drop_it_is_dropped_and_stays_pinned(self) -> None:
        self.listed(self.proxy(), tool())
        pinned = self.file.read_text(encoding="utf-8")
        p = self.proxy("drop")
        self.assertEqual(self.listed(p, tool("Keep notes for the user, version two.")), [])
        self.assertEqual(p.stats["dropped"], 1)
        self.assertEqual(self.file.read_text(encoding="utf-8"), pinned)
        self.assertEqual(len(self.listed(self.proxy("drop"), tool())), 1)  # the approved definition still passes

    def test_a_schema_only_change_is_detected(self) -> None:
        self.listed(self.proxy(), tool())
        changed = tool(inputSchema={"type": "object", "properties": {"text": {"type": "string"},
                                                                     "path": {"type": "string"}}})
        (seen,) = self.listed(self.proxy(), changed)
        self.assertIn("definition changed", seen["description"])
        for field, value in (("title", "Notes"), ("annotations", {"destructiveHint": True})):
            with self.subTest(field=field):
                self.assertNotEqual(tool_pin(tool(**{field: value})), tool_pin(tool()))

    def test_the_file_is_0600_in_a_0700_directory_and_holds_hashes_only(self) -> None:
        self.listed(self.proxy(), tool())
        self.assertEqual(stat.S_IMODE(self.file.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.file.parent.stat().st_mode) & 0o077, 0)
        text = self.file.read_text(encoding="utf-8")
        self.assertNotIn("Keep notes", text)
        self.assertEqual(json.loads(text), {"notes": tool_pin(tool())})
        self.assertEqual(sorted(p.name for p in self.file.parent.iterdir()), [self.file.name])  # no temp left

    def test_no_pins_file_writes_nothing(self) -> None:
        p = Proxy(SERVER, log=self.log)
        self.listed(p, tool())
        self.assertFalse(self.state.exists())


class TestFailures(PinsCase):
    def test_a_fault_before_the_rename_keeps_the_old_file(self) -> None:
        self.listed(self.proxy(), tool())
        before = self.file.read_text(encoding="utf-8")
        p = self.proxy()
        with mock.patch.object(proxy.os, "replace", side_effect=OSError(28, "No space left on device")):
            self.assertEqual(len(self.listed(p, tool("Keep notes, version two."))), 1)  # still relayed
            self.listed(p, tool("Keep notes, version three."))
        self.assertEqual(self.file.read_text(encoding="utf-8"), before)
        self.assertEqual(self.log.getvalue().count("pins not persisted (OSError); keeping them in memory"), 1)
        self.assertEqual(sorted(p.name for p in self.file.parent.iterdir()), [self.file.name])

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root can write anywhere")
    def test_an_unwritable_directory_keeps_relaying_with_pins_in_memory(self) -> None:
        self.file.parent.mkdir(parents=True)
        self.file.parent.chmod(0o500)
        self.addCleanup(self.file.parent.chmod, 0o700)
        p = self.proxy()
        self.listed(p, tool())
        (seen,) = self.listed(p, tool("Keep notes, version two."))
        self.assertIn("definition changed", seen["description"])  # the in-memory pin still works
        self.assertEqual(self.log.getvalue().count("pins not persisted"), 1)
        self.assertFalse(self.file.exists())

    def test_a_corrupt_pins_file_is_logged_and_treated_as_a_first_run(self) -> None:
        self.file.parent.mkdir(parents=True)
        for content in ("{not json", '["notes"]', '{"notes": 5}'):
            with self.subTest(content=content):
                self.file.write_text(content, encoding="utf-8")
                self.log = io.StringIO()
                p = self.proxy()
                (seen,) = self.listed(p, tool())
                self.assertNotIn("frisk:", seen["description"])
                self.assertIn("starting with no pins", self.log.getvalue())
                self.assertEqual(json.loads(self.file.read_text(encoding="utf-8")), {"notes": tool_pin(tool())})


class TestCliFlags(PinsCase):
    def proxy_args(self, argv: list[str]) -> dict:
        seen: dict = {}

        class Fake:
            def __init__(self, server_cmd: list[str], **kwargs: object) -> None:
                seen.update(kwargs, server_cmd=server_cmd)

            def run(self) -> int:
                return 0

        with mock.patch.object(cli.proxy, "Proxy", Fake):
            self.assertEqual(cli.main(["proxy", *argv]), 0)
        return seen

    def test_the_flags_reach_the_proxy(self) -> None:
        self.assertEqual(self.proxy_args(["--", *SERVER])["pins_file"], self.file)
        self.assertEqual(self.proxy_args(["--", *SERVER])["on_change"], "flag")
        self.assertIsNone(self.proxy_args(["--no-pins", "--", *SERVER])["pins_file"])
        self.assertEqual(self.proxy_args(["--pins", "p.json", "--", *SERVER])["pins_file"], Path("p.json"))
        self.assertEqual(self.proxy_args(["--on-change", "drop", "--", *SERVER])["on_change"], "drop")

    def test_pins_and_no_pins_together_are_refused(self) -> None:
        with mock.patch("sys.stderr", io.StringIO()), self.assertRaises(SystemExit) as raised:
            cli.main(["proxy", "--pins", "p.json", "--no-pins", "--", *SERVER])
        self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
