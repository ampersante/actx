import json
import os
import subprocess
import tempfile
import unittest
from unittest import mock

from actx_lib import cli

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACTX = os.path.realpath(os.path.join(ROOT, "actx"))


class BypassHelperTests(unittest.TestCase):
    def test_env_one_true(self):
        with mock.patch.dict(os.environ, {"ACTX_BYPASS": "1"}):
            self.assertTrue(cli._bypass_requested("git", {}))

    def test_env_other_false(self):
        with mock.patch.dict(os.environ, {"ACTX_BYPASS": "0"}):
            self.assertFalse(cli._bypass_requested("git", {}))

    def test_env_absent_false(self):
        with mock.patch.dict(os.environ, {"ACTX_BYPASS": ""}):
            self.assertFalse(cli._bypass_requested("git", {}))

    def test_config_list_contains(self):
        with mock.patch.dict(os.environ, {"ACTX_BYPASS": "0"}):
            self.assertTrue(
                cli._bypass_requested("git", {"bypass_commands": ["git"]})
            )

    def test_config_list_missing(self):
        with mock.patch.dict(os.environ, {"ACTX_BYPASS": "0"}):
            self.assertFalse(
                cli._bypass_requested("ls", {"bypass_commands": ["git"]})
            )

    def test_config_non_list_false(self):
        with mock.patch.dict(os.environ, {"ACTX_BYPASS": "0"}):
            self.assertFalse(
                cli._bypass_requested("git", {"bypass_commands": "git"})
            )


class BypassIntegrationTests(unittest.TestCase):
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

    def run_actx(self, args, extra_env=None):
        env = os.environ.copy()
        env["HOME"] = self.home.name
        if extra_env:
            env.update(extra_env)
        return subprocess.run(
            [ACTX] + args,
            capture_output=True,
            text=True,
            cwd=self.repo.name,
            env=env,
        )

    def write_config(self, bypass_commands):
        path = os.path.join(self.home.name, ".config", "actx", "config.json")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump({"bypass_commands": bypass_commands}, handle)

    def tee_dir(self):
        return os.path.join(self.home.name, ".local", "share", "actx", "tee")

    def _init_repo_with_change(self):
        self.git("init", "-q")
        self.git("config", "user.email", "a@b.c")
        self.git("config", "user.name", "tester")
        with open(os.path.join(self.repo.name, "f"), "w", encoding="utf-8") as handle:
            handle.write("a\n")
        self.git("add", ".")
        self.git("commit", "-m", "init")
        with open(os.path.join(self.repo.name, "f"), "w", encoding="utf-8") as handle:
            handle.write("a\nb\n")

    def test_env_bypass_runs_raw_git_status(self):
        self._init_repo_with_change()
        raw = self.git("status")

        p = self.run_actx(["git", "status"], {"ACTX_BYPASS": "1"})
        self.assertEqual(p.returncode, raw.returncode)
        self.assertEqual(p.stdout, raw.stdout)

        filtered = self.run_actx(["git", "status"])
        self.assertNotEqual(filtered.stdout, raw.stdout)

    def test_config_bypass_runs_raw_git_status(self):
        self.write_config(["git"])
        self._init_repo_with_change()
        raw = self.git("status")

        p = self.run_actx(["git", "status"])
        self.assertEqual(p.returncode, raw.returncode)
        self.assertEqual(p.stdout, raw.stdout)

    def test_env_bypass_run_skips_tee(self):
        p = self.run_actx(["run", "false"], {"ACTX_BYPASS": "1"})
        self.assertEqual(p.returncode, 1)
        self.assertFalse(os.path.isdir(self.tee_dir()))

    def test_config_bypass_run_skips_tee(self):
        self.write_config(["false"])
        p = self.run_actx(["run", "false"])
        self.assertEqual(p.returncode, 1)
        self.assertFalse(os.path.isdir(self.tee_dir()))

    def test_run_without_bypass_creates_tee(self):
        p = self.run_actx(["run", "false"])
        self.assertEqual(p.returncode, 1)
        self.assertTrue(os.path.isdir(self.tee_dir()))


if __name__ == "__main__":
    unittest.main()
