"""Surfaces: the regions of a file that the scan rules run on.

Each public module in this package exposes

    extract(path: Path, text: str) -> list[Span]

returning spans of `text` (offsets into the full file) and the kind of rules to run on
each: "code" (CODE_RULES) or "text" (TEXT_RULES and the hidden-Unicode check). The
engine runs every surface on every file it reads, so a new surface is one new module
here and no other edit. Modules whose names start with "_" are not surfaces.
"""
from __future__ import annotations

import functools
import importlib
import pkgutil
from collections.abc import Iterable
from types import ModuleType
from typing import NamedTuple


class Span(NamedTuple):
    start: int
    end: int
    kind: str  # "code" | "text"


def discover(path: Iterable[str], package: str) -> list[ModuleType]:
    """Import every public, non-package module found on `path` as `package.<name>`.

    Returned in name order so the scan is deterministic.
    """
    names = sorted(m.name for m in pkgutil.iter_modules(list(path))
                   if not m.ispkg and not m.name.startswith("_"))
    return [importlib.import_module(f"{package}.{name}") for name in names]


@functools.lru_cache(maxsize=None)
def load() -> tuple[ModuleType, ...]:
    """The surfaces shipped in this package, discovered once per process."""
    return tuple(discover(__path__, __name__))


def name_of(surface: ModuleType) -> str:
    return surface.__name__.rsplit(".", 1)[-1]
