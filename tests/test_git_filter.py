import io
import json
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from actx_lib.filters import git_filter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACTX = os.path.join(ROOT, "actx")


class GitFilterTests(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.TemporaryDirectory()
        self.repo = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.home.cleanup()
        self.repo.cleanup()

    def git(self, *args):
        return subprocess.run(
            ["git", "-C", self.repo.name] + list(args),
            capture_output=True,
            text=True,
        )

    def run_actx(self, *args):
        env = os.environ.copy()
        env["HOME"] = self.home.name
        return subprocess.run(
            [ACTX] + list(args),
            capture_output=True,
            text=True,
            cwd=self.repo.name,
            env=env,
        )

    def _init_repo(self):
        self.git("init", "-q")
        self.git("config", "user.email", "a@b.c")
        self.git("config", "user.name", "tester")

    def _write(self, name, content):
        with open(os.path.join(self.repo.name, name), "w", encoding="utf-8") as handle:
            handle.write(content)

    def _tee_files(self):
        tee_dir = os.path.join(
            self.home.name, ".local", "share", "actx", "tee"
        )
        if not os.path.isdir(tee_dir):
            return []
        return [f for f in os.listdir(tee_dir) if f.endswith(".log")]

    def test_git_status_compresses_modified_files(self):
        self._init_repo()
        names = ["f%02d" % i for i in range(60)]
        for name in names:
            self._write(name, "a\n")
        self.git("add", ".")
        self.git("commit", "-m", "init")
        for name in names:
            self._write(name, "a\nb\n")

        raw = self.git("status", "--porcelain=v1")
        self.assertEqual(raw.returncode, 0)

        p = self.run_actx("git", "status")
        self.assertEqual(p.returncode, 0)
        for name in names:
            self.assertIn(name, p.stdout)
        self.assertLess(
            len(p.stdout.encode("utf-8")),
            len(raw.stdout.encode("utf-8")),
        )

    def test_git_status_empty_repo(self):
        self._init_repo()
        p = self.run_actx("git", "status")
        self.assertEqual(p.returncode, 0)
        self.assertTrue(
            p.stdout == "no commits yet\n" or p.stdout.startswith("* "),
            p.stdout,
        )

    def test_git_diff_known_hunk_counts(self):
        self._init_repo()
        original = ["line%03d abcdefghij" % i for i in range(200)]
        original.insert(100, "remove_me")
        self._write("f", "\n".join(original) + "\n")
        self.git("add", ".")
        self.git("commit", "-m", "init")

        changed = list(original)
        changed[100] = "added_one"
        changed.insert(101, "added_two")
        self._write("f", "\n".join(changed) + "\n")

        p = self.run_actx("git", "diff", "-U100")
        self.assertEqual(p.returncode, 0)
        self.assertIn("+2 -1", p.stdout)
        self.assertNotIn("+6 -5", p.stdout)

    def test_git_diff_large_writes_tee_on_success(self):
        self._init_repo()
        original = ["line%03d abcdefghij" % i for i in range(200)]
        self._write("f", "\n".join(original) + "\n")
        self.git("add", ".")
        self.git("commit", "-m", "init")
        self._write("f", "\n".join(original) + "extra\n")

        p = self.run_actx("git", "diff", "-U100")
        self.assertEqual(p.returncode, 0)
        files = self._tee_files()
        self.assertEqual(len(files), 1)
        with open(
            os.path.join(self.home.name, ".local", "share", "actx", "tee", files[0]),
            encoding="utf-8",
        ) as handle:
            record = json.load(handle)
        self.assertEqual(record["exit_code"], 0)

    def test_git_diff_exit_code_passthrough(self):
        self._init_repo()
        self._write("f", "a\n")
        self.git("add", ".")
        self.git("commit", "-m", "init")
        self._write("f", "a\nb\n")

        p = self.run_actx("git", "diff", "--exit-code")
        self.assertEqual(p.returncode, 1)
        self.assertIn("diff --git", p.stdout)

    def test_git_branch_list_passthrough(self):
        self._init_repo()
        self._write("f", "a\n")
        self.git("add", ".")
        self.git("commit", "-m", "init")
        branch = self.git("symbolic-ref", "--short", "HEAD").stdout.strip()

        p = self.run_actx("git", "branch", "-a")
        self.assertEqual(p.returncode, 0)
        self.assertIn("* " + branch, p.stdout)

    def test_git_branch_create_confirms(self):
        self._init_repo()
        self._write("f", "a\n")
        self.git("add", ".")
        self.git("commit", "-m", "init")

        p = self.run_actx("git", "branch", "foo")
        self.assertEqual(p.returncode, 0)
        self.assertEqual(p.stdout, "ok\n")

    def test_git_status_filter_exception_falls_back_to_raw(self):
        self._init_repo()
        self._write("f", "a\n")
        self.git("add", ".")
        self.git("commit", "-m", "init")
        self._write("f", "a\nb\n")

        raw = self.git("status", "--porcelain=v1")
        config = {
            "tee": {"enabled": False, "mode": "failures", "dir": "~/.local/share/actx/tee"},
            "truncate": {"max_lines": 500, "max_line_chars": 300},
        }

        out = io.StringIO()
        err = io.StringIO()
        old_cwd = os.getcwd()
        try:
            os.chdir(self.repo.name)
            with mock.patch.object(git_filter, "_group_status", side_effect=RuntimeError("boom")):
                with redirect_stdout(out), redirect_stderr(err):
                    rc = git_filter.run(["status"], config)
        finally:
            os.chdir(old_cwd)

        self.assertEqual(rc, 0)
        self.assertEqual(out.getvalue(), raw.stdout)


if __name__ == "__main__":
    unittest.main()
