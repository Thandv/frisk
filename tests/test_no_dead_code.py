"""FR-E7 t6 (F4.03): no dead private names, every function typed, and the README's line count.

A stdlib ast pass over src/frisk: each module-level private name (one leading underscore, not
a dunder) is read in its own module or imported by another, and every function, private ones
too (mypy's disallow_untyped_defs covers frisk.*), annotates each parameter and its return.
Each check is shown to catch a planted case, parsed in memory and never written to a file.
Run: PYTHONPATH=src python3 -B -m unittest discover -s tests
"""
from __future__ import annotations

import ast
import re
import unittest

from _subproc import REPO

PACKAGE = REPO / "src" / "frisk"


def modules() -> dict[str, ast.Module]:
    return {str(p.relative_to(PACKAGE)): ast.parse(p.read_text(encoding="utf-8"))
            for p in sorted(PACKAGE.rglob("*.py"))}


def module_names(tree: ast.Module) -> list[str]:
    """Names bound at module level: functions, classes and assignment targets."""
    names = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.append(node.name)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            names += [n.id for t in targets for n in ast.walk(t) if isinstance(n, ast.Name)]
    return names


def dead_private_names(trees: dict[str, ast.Module]) -> list[str]:
    imported = {a.name for t in trees.values() for n in ast.walk(t) if isinstance(n, ast.ImportFrom) for a in n.names}
    dead = []
    for name, tree in trees.items():
        read = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}
        dead += [f"{name}: {v}" for v in module_names(tree)
                 if v.startswith("_") and not v.startswith("__") and v not in read and v not in imported]
    return dead


def untyped(trees: dict[str, ast.Module]) -> list[str]:
    found = []
    for name, tree in trees.items():
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                a = node.args
                params = [*a.posonlyargs, *a.args, *a.kwonlyargs, *(p for p in (a.vararg, a.kwarg) if p)]
                bare = [p.arg for p in params if p.annotation is None and p.arg not in ("self", "cls")]
                if bare or node.returns is None:
                    found.append(f"{name}:{node.lineno} {node.name}")
    return found


class TestDeadCode(unittest.TestCase):
    def test_no_dead_private_module_names(self) -> None:
        self.assertEqual(dead_private_names(modules()), [])

    def test_the_check_catches_a_planted_dead_name(self) -> None:
        planted = {"a.py": ast.parse("_USED = 1\n_UNUSED = 2\n_SHARED = 3\ndef _helper() -> int:\n    return _USED\n"),
                   "b.py": ast.parse("from .a import _SHARED\n")}
        self.assertEqual(dead_private_names(planted), ["a.py: _UNUSED", "a.py: _helper"])


class TestTyped(unittest.TestCase):
    def test_every_function_is_annotated(self) -> None:
        self.assertEqual(untyped(modules()), [])

    def test_the_check_catches_planted_untyped_functions(self) -> None:
        planted = {"c.py": ast.parse("def ok(x: int, *a: str, **k: str) -> None: ...\n"
                                     "def no_return(x: int): ...\n"
                                     "def bare_param(x) -> None: ...\n"
                                     "class C:\n    def m(self, y) -> None: ...\n    def n(self) -> int: ...\n")}
        self.assertEqual(untyped(planted), ["c.py:2 no_return", "c.py:3 bare_param", "c.py:5 m"])


class TestLineCount(unittest.TestCase):
    def test_the_readme_states_the_source_size(self) -> None:
        # Method: every non-blank line of src/frisk/**/*.py, rounded to the nearest hundred.
        lines = sum(1 for p in PACKAGE.rglob("*.py") for line in p.read_text(encoding="utf-8").splitlines()
                    if line.strip())
        readme = (REPO / "README.md").read_text(encoding="utf-8")
        stated = re.search(r"about ([\d,]+) lines of Python, counting every non-blank line", readme)
        self.assertIsNotNone(stated)
        assert stated is not None
        self.assertEqual(int(stated.group(1).replace(",", "")), round(lines, -2))


if __name__ == "__main__":
    unittest.main()
