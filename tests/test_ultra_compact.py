import os
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACTX = os.path.join(ROOT, "actx")


class UltraCompactTests(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.TemporaryDirectory()
        self.work = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.home.cleanup()
        self.work.cleanup()

    def run_actx(self, *args):
        env = os.environ.copy()
        env["HOME"] = self.home.name
        return subprocess.run(
            [ACTX] + list(args),
            capture_output=True,
            text=True,
            cwd=self.work.name,
            env=env,
        )

    def test_git_status_ultra_is_shorter(self):
        subprocess.run(["git", "init", "-q"], cwd=self.work.name, check=True)
        subprocess.run(
            ["git", "config", "user.email", "a@b.c"],
            cwd=self.work.name,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "a"],
            cwd=self.work.name,
            check=True,
        )
        for name in ("one.txt", "two.txt", "three.txt"):
            with open(os.path.join(self.work.name, name), "w", encoding="utf-8") as handle:
                handle.write("x\n")

        normal = self.run_actx("git", "status")
        ultra = self.run_actx("--ultra-compact", "git", "status")
        self.assertEqual(normal.returncode, 0, normal.stderr)
        self.assertEqual(ultra.returncode, 0, ultra.stderr)
        self.assertIn("??", normal.stdout)
        self.assertIn("??", ultra.stdout)
        self.assertLess(len(ultra.stdout.encode()), len(normal.stdout.encode()))

    def test_ls_ultra_is_shorter(self):
        for name in ("a.txt", "b.txt", "c.txt", "d.txt", "e.txt"):
            with open(os.path.join(self.work.name, name), "w", encoding="utf-8") as handle:
                handle.write("x\n")

        normal = self.run_actx("ls")
        ultra = self.run_actx("--ultra-compact", "ls")
        self.assertEqual(normal.returncode, 0, normal.stderr)
        self.assertEqual(ultra.returncode, 0, ultra.stderr)
        self.assertIn("a.txt", normal.stdout)
        self.assertIn("a.txt", ultra.stdout)
        self.assertLess(len(ultra.stdout.encode()), len(normal.stdout.encode()))


if __name__ == "__main__":
    unittest.main()
