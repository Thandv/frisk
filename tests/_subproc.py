"""Run `python -m frisk.cli` as a child process, the way a user does (not a test module: no test_ prefix).

The child gets a small, fixed environment: PYTHONPATH=src, NO_COLOR=1, COLUMNS=100 (argparse
wraps help to it), UTF-8 stdio, and a temp HOME and XDG_STATE_HOME, so nothing reads the real
home directory, the real package caches or the real proxy pins.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "src"


def child_env(home: str, **extra: str) -> dict[str, str]:
    """The child's environment: PATH from this process, everything else fixed."""
    env = {"PATH": os.environ.get("PATH", ""), "PYTHONPATH": str(SRC), "NO_COLOR": "1", "COLUMNS": "100",
           "PYTHONIOENCODING": "utf-8", "HOME": home, "XDG_STATE_HOME": os.path.join(home, "state")}
    env.update(extra)
    return env


def run_cli(args: list[str], stdin: bytes | None = None, cwd: Path = REPO, timeout: float = 60,
            env: dict[str, str] | None = None, python: str = sys.executable) -> subprocess.CompletedProcess[bytes]:
    """Run `python -m frisk.cli ARGS` in `cwd` (default: the repo root) and capture its output.

    `stdin` is the child's whole input (None: an empty /dev/null). `env` entries are added to
    child_env(); a key mapped to "" is removed instead."""
    with tempfile.TemporaryDirectory() as home:
        full = child_env(home)
        for key, value in (env or {}).items():
            if value == "":
                full.pop(key, None)
            else:
                full[key] = value
        argv = [python, "-B", "-m", "frisk.cli", *args]
        if stdin is None:  # never the test runner's own stdin
            return subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, cwd=str(cwd), env=full,
                                  timeout=timeout, check=False)
        return subprocess.run(argv, input=stdin, capture_output=True, cwd=str(cwd), env=full, timeout=timeout,
                              check=False)
