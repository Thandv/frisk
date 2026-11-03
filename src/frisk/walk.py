"""The one directory walker: engine scans and pin fingerprints both walk with it.

It never follows a symlink. The tree is listed with os.walk(followlinks=False) and every
file entry is classified with os.lstat, so a link is reported as a link (its target is the
caller's decision, see read_link), and a FIFO, socket or device is reported as special and
never opened. A symlinked directory is listed, never entered, so a link loop ends.
"""
from __future__ import annotations

import errno
import os
import stat
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

# Under $HOME: where SSH, GnuPG and cloud credentials live. A link to one of them (or to a
# directory holding one, such as $HOME itself) is a block-level escape.
CREDENTIAL_LOCATIONS = (".ssh", ".aws", ".gnupg", ".config/gcloud", ".azure", ".kube", ".docker/config.json",
                        ".netrc")


@dataclass(frozen=True)
class Entry:
    """One entry of a walk. kind: 'dir' (a directory is about to be listed), 'vcs' (a .git
    directory, not entered; nested when below the top), 'dir_link' (a symlinked directory,
    not entered), 'file' (a regular file), 'link' (a symlink that is not to a directory) or
    'special' (a FIFO, socket or device: never opened; detail names which)."""
    kind: str
    path: Path
    nested: bool = False
    detail: str = ""


@dataclass(frozen=True)
class Link:
    """What a symlink points to: `text` as os.readlink gives it, `real` its resolved path,
    whether that lies inside the scan root, and whether it is (or holds) a credential location."""
    text: str
    real: Path
    inside: bool
    credential: bool


def entries(top: Path, onerror: Callable[[OSError], None] | None = None) -> Iterator[Entry]:
    """Every entry below `top`, each directory's entries in name order (.git first, then the
    symlinked directories, then the files); .git directories are reported, never entered."""
    for dirpath, dirnames, filenames in os.walk(top, onerror=onerror, followlinks=False):
        here = Path(dirpath)
        yield Entry("dir", here)
        dirnames.sort()
        if ".git" in dirnames:  # the VCS directory itself, once
            dirnames.remove(".git")
            yield Entry("vcs", here / ".git", nested=here != top)
        for name in dirnames:
            if os.path.islink(here / name):
                yield Entry("dir_link", here / name)
        for name in sorted(filenames):
            path = here / name
            try:
                mode = os.lstat(path).st_mode
            except OSError:  # gone since it was listed: nothing to read
                continue
            if stat.S_ISREG(mode):
                yield Entry("file", path)
            elif stat.S_ISLNK(mode):
                yield Entry("link", path)
            else:
                yield Entry("special", path, detail=special_kind(mode))


def special_kind(mode: int) -> str:
    """'fifo', 'socket', 'device' or 'other' for a file mode that is not a regular file."""
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISSOCK(mode):
        return "socket"
    if stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
        return "device"
    return "other"


def read_link(link: Path, root_real: Path) -> Link:
    """Where `link` points, judged against the scan root (`root_real`, symlinks resolved).
    Only paths are read: the target is never opened."""
    text = os.readlink(link)
    real = Path(os.path.realpath(link))
    inside = real == root_real or root_real in real.parents
    return Link(text, real, inside, not inside and _credential(real))


def is_loop(path: Path) -> bool:
    """Whether resolving the symlink at `path` loops."""
    try:
        os.stat(path)
    except OSError as e:
        return e.errno == errno.ELOOP
    return False


def _credential(real: Path) -> bool:
    for location in CREDENTIAL_LOCATIONS:
        base = Path(os.path.realpath(os.path.expanduser("~/" + location)))
        if real == base or base in real.parents or real in base.parents:
            return True
    return False
