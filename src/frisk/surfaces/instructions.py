"""Agent-instruction files (SKILL.md, agents/*.md, commands/*.md, CLAUDE.md, AGENTS.md,
.cursorrules, *.mdc): the whole file also gets the instruction rules, which address the
agent and would be too noisy in ordinary docs such as a README."""
from __future__ import annotations

from pathlib import Path

from . import Span

_NAMES = {"skill.md", "claude.md", "agents.md", ".cursorrules"}


def is_instruction_file(path: Path) -> bool:
    name, ext = path.name.lower(), path.suffix.lower()
    return (name in _NAMES or ext == ".mdc"
            or (ext == ".md" and path.parent.name.lower() in ("agents", "commands")))


def extract(path: Path, text: str) -> list[Span]:
    return [Span(0, len(text), "instruction")] if is_instruction_file(path) else []
