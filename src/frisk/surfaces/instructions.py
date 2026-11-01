"""Agent-instruction files (SKILL.md, agents/*.md, commands/*.md, CLAUDE.md, CLAUDE.local.md,
AGENTS.md, .cursorrules, *.mdc, and any .md below .claude/agents, commands, rules, skills or
output-styles): the whole file also gets the instruction rules, which address the agent and
would be too noisy in ordinary docs such as a README. Names match in any case, as the
macOS and Windows file systems do."""
from __future__ import annotations

from pathlib import Path

from . import Span

_NAMES = {"skill.md", "claude.md", "claude.local.md", "agents.md", ".cursorrules"}
# Claude Code loads the markdown at any depth below these .claude/ directories: namespaced
# commands, nested rules, a skill's reference files.
_CLAUDE_TREES = {"agents", "commands", "rules", "skills", "output-styles"}


def is_instruction_file(path: Path) -> bool:
    name, ext = path.name.lower(), path.suffix.lower()
    dirs = [part.lower() for part in path.parent.parts]
    in_claude_tree = any(a == ".claude" and b in _CLAUDE_TREES for a, b in zip(dirs, dirs[1:]))
    return (name in _NAMES or ext == ".mdc"
            or (ext == ".md" and (path.parent.name.lower() in ("agents", "commands") or in_claude_tree)))


def extract(path: Path, text: str) -> list[Span]:
    return [Span(0, len(text), "instruction")] if is_instruction_file(path) else []
