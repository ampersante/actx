import json
import os
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACTX = os.path.join(ROOT, "actx")


class RunnerCliTests(unittest.TestCase):
    def run_actx(self, args, home):
        env = os.environ.copy()
        env["HOME"] = home
        return subprocess.run(
            [ACTX] + args,
            capture_output=True,
            text=True,
            env=env,
        )

    def test_run_false_creates_tee_file_with_exit_code_1(self):
        with tempfile.TemporaryDirectory() as home:
            p = self.run_actx(["run", "false"], home)
            self.assertEqual(p.returncode, 1)
            tee_dir = os.path.join(home, ".local", "share", "actx", "tee")
            files = os.listdir(tee_dir)
            self.assertEqual(len(files), 1)
            with open(os.path.join(tee_dir, files[0]), encoding="utf-8") as handle:
                record = json.load(handle)
            self.assertEqual(record["exit_code"], 1)

    def test_git_status_outside_repo_exits_128(self):
        with tempfile.TemporaryDirectory() as home:
            with tempfile.TemporaryDirectory() as workdir:
                p = subprocess.run(
                    [ACTX, "git", "status"],
                    capture_output=True,
                    text=True,
                    cwd=workdir,
                    env={**os.environ, "HOME": home},
                )
                self.assertEqual(p.returncode, 128)


if __name__ == "__main__":
    unittest.main()
