"""Surfaces: the regions of a file that the scan rules run on.

Each public module in this package exposes

    extract(path: Path, text: str) -> list[Span]

returning spans of `text` (offsets into the full file) and the kind of rules to run on
each: "code" (CODE_RULES), "md_inline_code" (CODE_RULES capped at warn: inline code in
an ordinary markdown document), "instruction" (INSTRUCTION_RULES) or a text kind ("text", or a
label such as "md_html_comment" for a region renderers hide): TEXT_RULES and the
hidden-Unicode check. A span whose content is not a stretch of the file (a JSON string as
it decodes) carries that content as `text`; its findings are reported at the line of
`start`. The engine runs every surface on every file it reads, so a new surface is one new module
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
    kind: str  # "code" | "md_inline_code" | "instruction" | "text" | another text label such as "md_html_comment"
    text: str | None = None  # the content scanned instead of file[start:end], when given


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
