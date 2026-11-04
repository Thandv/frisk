"""Load a file under scripts/ as a module (not a test module: no test_ prefix)."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from unittest import mock

REPO = Path(__file__).resolve().parent.parent


def load_script(name: str) -> ModuleType:
    """scripts/<name>.py as a module, without writing its bytecode into the repo."""
    spec = importlib.util.spec_from_file_location(name, REPO / "scripts" / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # dataclasses look their module up there
    with mock.patch.object(sys, "dont_write_bytecode", True):
        spec.loader.exec_module(module)
    return module
