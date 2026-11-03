"""FR-E6 F3.07b: a package frisk finds in the local cache is pinned by its content.

frisk lock reuses FR-E4's cache lookup (pkgcache, through sources) and fingerprints the
cached package with the shared walker, so a content change in the cache is DRIFT, a link
in the package is pinned by where it points (never its target's bytes), and a package not
in the cache is said at lock time (its code is not pinned) without being an error.
Fake npx and uv caches under a temp HOME, pointed at with FRISK_NPX_CACHE and
FRISK_UV_TOOLS; the real caches are never read.
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

from _home import fake_home
from frisk import pin
from frisk.cli import main


def run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class CacheCase(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(os.path.realpath(tmp.name))
        fake_home(self, self.tmp / "home")
        (self.tmp / "home").mkdir()
        self.npx_root, self.uv_root = self.tmp / "npx", self.tmp / "uv-tools"
        patcher = mock.patch.dict(os.environ, {"FRISK_NPX_CACHE": str(self.npx_root),
                                               "FRISK_UV_TOOLS": str(self.uv_root)})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.cfg = self.tmp / "mcp.json"
        self.lockfile = self.tmp / "lock.json"

    def npx_package(self, name: str, version: str) -> Path:
        entry = self.npx_root / "0a1b2c3d"
        pkg = entry / "node_modules" / name
        pkg.mkdir(parents=True)
        (entry / "package.json").write_text(json.dumps({"dependencies": {name: "^" + version}}), encoding="utf-8")
        (pkg / "package.json").write_text(json.dumps({"name": name, "version": version}), encoding="utf-8")
        (pkg / "index.js").write_text("module.exports = 1\n", encoding="utf-8")
        return pkg

    def uv_tool(self, dist: str, version: str) -> Path:
        site = self.uv_root / dist / "lib" / "python3.12" / "site-packages"
        module = site / dist.replace("-", "_")
        module.mkdir(parents=True)
        (module / "server.py").write_text("x = 1\n", encoding="utf-8")
        info = site / f"{dist.replace('-', '_')}-{version}.dist-info"
        info.mkdir()
        (info / "METADATA").write_text(f"Metadata-Version: 2.1\nName: {dist}\nVersion: {version}\n\n",
                                       encoding="utf-8")
        (info / "RECORD").write_text(f"{module.name}/server.py,sha256=x,1\n", encoding="utf-8")
        return module

    def lock(self, servers: dict) -> str:
        self.cfg.write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")
        code, _out, err = run(["lock", "--mcp-config", str(self.cfg), "--lockfile", str(self.lockfile)])
        self.assertEqual(code, 0, err)
        return err

    def row(self, name: str) -> dict:
        report = pin.verify_lock(pin.read_lock(str(self.lockfile)), self.lockfile.parent)
        (row,) = [r for r in report if r["entry"] == f"{self.cfg}::{name}"]
        return row


class TestCachedContent(CacheCase):
    def test_a_content_change_in_the_npx_cache_is_drift(self) -> None:
        pkg = self.npx_package("acme-notes", "1.0.0")
        self.lock({"n": {"command": "npx", "args": ["-y", "acme-notes@1.0.0"]}})
        self.assertEqual(self.row("n")["status"], "ok")
        (pkg / "index.js").write_text("module.exports = 2\n", encoding="utf-8")
        row = self.row("n")
        self.assertEqual((row["status"], row["changed"]), ("DRIFT", ["index.js"]))

    def test_a_content_change_in_a_uv_tool_is_drift(self) -> None:
        module = self.uv_tool("acme-py", "1.2.0")
        self.lock({"u": {"command": "uvx", "args": ["acme-py==1.2.0"]}})
        self.assertEqual(self.row("u")["status"], "ok")
        (module / "server.py").write_text("x = 2\n", encoding="utf-8")
        self.assertEqual(self.row("u")["status"], "DRIFT")

    def test_a_link_in_a_cached_package_is_pinned_by_where_it_points(self) -> None:
        pkg = self.npx_package("acme-notes", "1.0.0")
        outside = self.tmp / "outside.js"
        outside.write_text("a\n", encoding="utf-8")
        (pkg / "extra.js").symlink_to(outside)
        self.lock({"n": {"command": "npx", "args": ["acme-notes@1.0.0"]}})
        outside.write_text("b\n", encoding="utf-8")
        self.assertEqual(self.row("n")["status"], "ok")  # outside content is never read
        os.remove(pkg / "extra.js")
        (pkg / "extra.js").symlink_to(self.tmp / "other.js")
        self.assertEqual(self.row("n")["changed"], ["extra.js"])


class TestCacheMiss(CacheCase):
    def test_a_miss_is_said_at_lock_time_and_is_not_an_error(self) -> None:
        err = self.lock({"m": {"command": "npx", "args": ["acme-missing@1.0.0"]}})
        self.assertEqual(err, f"frisk lock: {self.cfg}::m: code not pinned, only how it starts "
                              "(not in local cache; frisk does not download)\n")
        self.assertEqual(self.row("m")["status"], "ok")
        code, out, _ = run(["verify", "--lockfile", str(self.lockfile)])
        self.assertEqual(code, 0, out)

    def test_a_package_that_appears_in_the_cache_later_is_drift(self) -> None:
        self.lock({"m": {"command": "npx", "args": ["acme-notes@1.0.0"]}})
        self.npx_package("acme-notes", "1.0.0")
        self.assertEqual(self.row("m")["status"], "DRIFT")


if __name__ == "__main__":
    unittest.main()
