"""Rewrite README.md's demo blocks from real frisk runs.

A demo block is everything between a `<!-- frisk-demo: NAME -->` line and the next
`<!-- /frisk-demo -->` line, NAME being one of DEMOS. Each is rebuilt from the output of
`python -m frisk.cli ARGS` (PYTHONPATH=src, NO_COLOR=1), run in a fresh sandbox: a temp
working directory holding a copy of examples/ and a fixture MCP config, and a temp HOME
holding the same config where the README names it (~/.claude.json and Claude Desktop's
config path) and one cached npx package. Arguments are relative, so no temp path reaches
the output. Nothing in the repository is written except README.md, and only without --check.

  python3 scripts/gen_readme_demo.py           rewrite README.md
  python3 scripts/gen_readme_demo.py --check   exit 1 if a block is stale (writes nothing)

tests/test_docs.py fails when a block differs from render(); tests/test_readme_commands.py
runs the README's frisk commands through run_frisk() in a sandbox().
"""
from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
README = REPO / "README.md"
TIMEOUT_S = 60.0
BLOCK = re.compile(r"(<!-- frisk-demo: ([\w-]+) -->\n)(.*?)(<!-- /frisk-demo -->)", re.DOTALL)
CONFIG_NAME = "claude_desktop_config.json"
# Where the README's commands name a config under ~; the sandbox HOME holds the fixture at each.
HOME_CONFIGS = (".claude.json", "Library/Application Support/Claude/claude_desktop_config.json")
NPX_HASH = "9f86d081884c7d65"


@dataclass(frozen=True)
class Sandbox:
    cwd: Path   # a copy of examples/, the fixture config and the local server it names
    home: Path  # HOME and XDG_STATE_HOME/..: the fixture config at HOME_CONFIGS, one cached npx package


def _fixture_servers(cwd: Path) -> dict[str, object]:
    """One server of each kind the audit reports: local, a cached package, remote, an uncached package."""
    script = cwd / "notes" / "server.py"
    script.parent.mkdir()
    script.write_text('print("hello")\n', encoding="utf-8")
    return {
        "notes-server": {"command": "python3", "args": [str(script)]},
        "weather": {"command": "npx", "args": ["-y", "acme-weather"]},
        "some-remote": {"url": "https://mcp.example.invalid/sse"},
        "npm-tool": {"command": "npx", "args": ["-y", "some-npm-mcp"]},
    }


def _cache_npx_package(home: Path) -> None:
    """acme-weather 1.4.2 in npx's cache, with one declared dependency."""
    pkg = home / ".npm" / "_npx" / NPX_HASH
    (pkg / "node_modules" / "acme-weather").mkdir(parents=True)
    (pkg / "package.json").write_text(json.dumps({"dependencies": {"acme-weather": "^1.4.2"}}), encoding="utf-8")
    (pkg / "node_modules" / "acme-weather" / "package.json").write_text(
        json.dumps({"version": "1.4.2", "dependencies": {"zod": "^3.23.8"}}), encoding="utf-8")
    (pkg / "node_modules" / "acme-weather" / "index.js").write_text("console.log(1)\n", encoding="utf-8")


@contextlib.contextmanager
def sandbox() -> Iterator[Sandbox]:
    """A fresh working directory and HOME in a temp directory, removed afterwards."""
    with tempfile.TemporaryDirectory() as tmp:
        box = Sandbox(Path(tmp) / "work", Path(tmp) / "home")
        shutil.copytree(REPO / "examples", box.cwd / "examples")
        config = json.dumps({"mcpServers": _fixture_servers(box.cwd)}, indent=2)
        (box.cwd / CONFIG_NAME).write_text(config, encoding="utf-8")
        for rel in HOME_CONFIGS:
            (box.home / rel).parent.mkdir(parents=True, exist_ok=True)
            (box.home / rel).write_text(config, encoding="utf-8")
        _cache_npx_package(box.home)
        yield box


def run_frisk(args: list[str], box: Sandbox, stdin: bytes = b"") -> subprocess.CompletedProcess[bytes]:
    """`frisk ARGS` as `python -m frisk.cli ARGS` in the sandbox: no shell, a timeout, a fixed environment."""
    env = {"PATH": os.environ.get("PATH", ""), "PYTHONPATH": str(REPO / "src"), "NO_COLOR": "1", "COLUMNS": "100",
           "PYTHONIOENCODING": "utf-8", "PYTHONDONTWRITEBYTECODE": "1", "HOME": str(box.home),
           "XDG_STATE_HOME": str(box.home / "state")}
    return subprocess.run([sys.executable, "-B", "-m", "frisk.cli", *args], input=stdin, capture_output=True,
                          cwd=str(box.cwd), env=env, timeout=TIMEOUT_S, check=False)


def _session(box: Sandbox, args: list[str]) -> str:
    """`$ frisk ARGS` and what it printed to stdout."""
    out = run_frisk(args, box).stdout.decode("utf-8")
    return f"$ frisk {' '.join(args)}\n{out}"


def _scan(box: Sandbox) -> str:
    return _session(box, ["examples/malicious-skill"])


def _mcp_audit(box: Sandbox) -> str:
    return _session(box, ["--mcp-config", CONFIG_NAME])


def _drift(box: Sandbox) -> str:
    """Lock a skill and the config, change the local server's code, verify."""
    lock = run_frisk(["lock", "examples/clean-skill", "--mcp-config", CONFIG_NAME], box)
    if lock.returncode != 0:
        raise RuntimeError(f"frisk lock failed: {lock.stderr.decode('utf-8', 'replace')}")
    with open(box.cwd / "notes" / "server.py", "a", encoding="utf-8") as fh:
        fh.write('print("changed")\n')
    return _session(box, ["verify"])


DEMOS = {"scan": _scan, "mcp-audit": _mcp_audit, "drift": _drift}


def render(text: str) -> str:
    """`text` (a README) with every demo block rebuilt; an unknown demo name raises ValueError."""
    def block(m: re.Match[str]) -> str:
        name = m.group(2)
        if name not in DEMOS:
            raise ValueError(f"unknown frisk-demo block: {name}")
        with sandbox() as box:
            body = DEMOS[name](box)
        body = body.rstrip("\n")
        return f"{m.group(1)}```\n{body}\n```\n{m.group(4)}"
    return BLOCK.sub(block, text)


def main(argv: list[str]) -> int:
    check = argv == ["--check"]
    if argv and not check:
        print("usage: gen_readme_demo.py [--check]", file=sys.stderr)
        return 2
    current = README.read_text(encoding="utf-8")
    fresh = render(current)
    if fresh == current:
        return 0
    if check:
        print("README.md demo blocks are stale: run python3 scripts/gen_readme_demo.py", file=sys.stderr)
        return 1
    README.write_text(fresh, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
