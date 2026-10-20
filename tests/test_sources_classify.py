"""Characterization table for sources._classify: pins TODAY's ServerRef for each server shape.

Run: PYTHONPATH=src python3 -m unittest discover -s tests
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from frisk.sources import ServerRef, _classify

NPM_DETAIL = "npm package — fetch+scan not yet supported (roadmap)"
PYPI_DETAIL = "pypi package — fetch+scan not yet supported (roadmap)"
REMOTE_DETAIL = "remote HTTP/SSE server — behavior not statically verifiable"


class TestClassifyTable(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.script = self.dir / "server.py"
        self.script.write_text('print("hello")\n', encoding="utf-8")

    def test_table(self) -> None:
        d, script = str(self.dir), str(self.script)
        rows: list[tuple[str, dict[str, object], ServerRef]] = [
            ("npx", {"command": "npx", "args": ["-y", "@acme/weather-mcp"]},
             ServerRef("s", "package", "@acme/weather-mcp", False, NPM_DETAIL)),
            ("npx by absolute path", {"command": "/opt/bin/npx", "args": ["acme-mcp"]},
             ServerRef("s", "package", "acme-mcp", False, NPM_DETAIL)),
            ("npx without a package arg", {"command": "npx", "args": ["-y"]},
             ServerRef("s", "package", "npx", False, NPM_DETAIL)),
            ("uvx", {"command": "uvx", "args": ["acme-mcp-server"]},
             ServerRef("s", "package", "acme-mcp-server", False, PYPI_DETAIL)),
            ("url", {"url": "https://mcp.example.invalid/sse"},
             ServerRef("s", "remote", "https://mcp.example.invalid/sse", False, REMOTE_DETAIL)),
            ("serverUrl", {"serverUrl": "https://mcp.example.invalid/mcp"},
             ServerRef("s", "remote", "https://mcp.example.invalid/mcp", False, REMOTE_DETAIL)),
            ("url wins over command", {"url": "https://a.example.invalid", "command": "npx"},
             ServerRef("s", "remote", "https://a.example.invalid", False, REMOTE_DETAIL)),
            ("absolute local script", {"command": "python3", "args": [script]},
             ServerRef("s", "local", d, True, "local source via python3")),
            ("interpreter by absolute path", {"command": "/opt/bin/python3", "args": [script]},
             ServerRef("s", "local", d, True, "local source via python3")),
            ("local directory arg", {"command": "node", "args": [d]},
             ServerRef("s", "local", d, True, "local source via node")),
            ("command is a local file", {"command": script},
             ServerRef("s", "local", script, True, "local executable/script")),
            ("unresolvable command", {"command": "/nonexistent.invalid/bin/srv", "args": ["x"]},
             ServerRef("s", "unknown", "/nonexistent.invalid/bin/srv", False,
                       "could not resolve a local source to scan")),
            ("empty spec", {},
             ServerRef("s", "unknown", "?", False, "could not resolve a local source to scan")),
            # Today `uv` counts as a package runner and the first non-flag argument
            # (here the --directory value) is taken as the package name, so a local
            # uv project is reported as an unscannable pypi package. Pinned as-is;
            # FR-E4 changes this row to classify it as local source.
            ("uv --directory <dir> run server.py",
             {"command": "uv", "args": ["--directory", d, "run", "server.py"]},
             ServerRef("s", "package", d, False, PYPI_DETAIL)),
        ]
        for label, spec, expected in rows:
            with self.subTest(label):
                self.assertEqual(_classify("s", spec), expected)


if __name__ == "__main__":
    unittest.main()
