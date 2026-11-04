"""Check that a release tag names the version being built: exit 0 when TAG is 'v' + __version__.

usage: python scripts/check_tag_version.py TAG

__version__ is read from src/frisk/__init__.py as text; the package is not imported. Any
other tag (empty, missing, without the 'v', or another version) exits 1 with one line on
stderr. The publish workflow runs this before it builds anything.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

INIT = Path(__file__).resolve().parent.parent / "src" / "frisk" / "__init__.py"
VERSION = re.compile(r"""^__version__ = (["'])(?P<version>[^"']+)\1$""", re.MULTILINE)


def read_version(init: Path = INIT) -> str:
    """__version__ as written in `init`; ValueError if it is not there."""
    match = VERSION.search(init.read_text(encoding="utf-8"))
    if match is None:
        raise ValueError(f"no __version__ = \"...\" line in {init}")
    return match.group("version")


def problem(tag: str, version: str) -> str | None:
    """Why `tag` is not the release tag of `version`, or None when it is."""
    expected = "v" + version
    if tag == expected:
        return None
    if not tag:
        return f"no release tag given; expected {expected}"
    if not tag.startswith("v"):
        return f"release tag {tag!r} does not start with 'v'; expected {expected}"
    return f"release tag {tag!r} does not match __version__ {version!r}; expected {expected}"


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("check_tag_version: usage: check_tag_version.py TAG", file=sys.stderr)
        return 1
    try:
        why = problem(argv[0], read_version())
    except (OSError, ValueError) as e:
        print(f"check_tag_version: {e}", file=sys.stderr)
        return 1
    if why is not None:
        print(f"check_tag_version: {why}", file=sys.stderr)
        return 1
    print(f"check_tag_version: {argv[0]} matches __version__")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
