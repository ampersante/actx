import os
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACTX = os.path.join(ROOT, "actx")


class SystemFilterTests(unittest.TestCase):
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

    def run_raw(self, *args):
        return subprocess.run(
            list(args),
            capture_output=True,
            text=True,
            cwd=self.work.name,
        )

    def _write(self, name, content):
        with open(os.path.join(self.work.name, name), "w", encoding="utf-8") as handle:
            handle.write(content)

    def test_ls_lists_directory_grouped(self):
        os.makedirs(os.path.join(self.work.name, "sub"))
        self._write("sub/b.txt", "b")
        self._write("sub/a.txt", "a")
        self._write("top.txt", "t")

        p = self.run_actx("ls")
        self.assertEqual(p.returncode, 0)
        self.assertIn("top.txt", p.stdout)
        self.assertIn("sub", p.stdout)

    def test_ls_single_file_prints_name(self):
        self._write("a.txt", "a")
        p = self.run_actx("ls", "a.txt")
        self.assertEqual(p.returncode, 0)
        self.assertEqual(p.stdout, "a.txt\n")

    def test_ls_flags_passthrough(self):
        self._write("a.txt", "a")
        raw = self.run_raw("ls", "-la")
        p = self.run_actx("ls", "-la")
        self.assertEqual(p.returncode, raw.returncode)
        self.assertEqual(p.stdout, raw.stdout)

    def test_find_ls_passthrough_verbatim(self):
        self._write("a.txt", "a")
        raw = self.run_raw("find", ".", "-ls")
        p = self.run_actx("find", ".", "-ls")
        self.assertEqual(p.returncode, raw.returncode)
        self.assertEqual(p.stdout, raw.stdout)

    def test_find_delete_passthrough_verbatim(self):
        self._write("a.txt", "a")
        raw = self.run_raw("find", ".", "-delete")
        self.assertEqual(raw.returncode, 0)
        self._write("a.txt", "a")
        p = self.run_actx("find", ".", "-delete")
        self.assertEqual(p.returncode, 0)
        self.assertEqual(p.stdout, "")
        self.assertFalse(os.path.exists(os.path.join(self.work.name, "a.txt")))

    def test_find_groups_by_directory(self):
        os.makedirs(os.path.join(self.work.name, "sub"))
        for i in range(30):
            self._write("sub/f%02d.txt" % i, "x")
        p = self.run_actx("find", ".", "-name", "*.txt")
        self.assertEqual(p.returncode, 0)
        self.assertIn("./sub (30):", p.stdout)
        self.assertIn("f00.txt", p.stdout)

    def test_grep_quiet_passthrough_empty_stdout(self):
        self._write("f.txt", "match\n")
        p = self.run_actx("grep", "-q", "match", "f.txt")
        self.assertEqual(p.returncode, 0)
        self.assertEqual(p.stdout, "")

    def test_grep_context_passthrough(self):
        self._write("f.txt", "match\n")
        raw = self.run_raw("grep", "-A5", "match", "f.txt")
        p = self.run_actx("grep", "-A5", "match", "f.txt")
        self.assertEqual(p.returncode, raw.returncode)
        self.assertEqual(p.stdout, raw.stdout)

    def test_grep_no_matches_prints_no_matches(self):
        self._write("f.txt", "content\n")
        p = self.run_actx("grep", "zzz", "f.txt")
        self.assertEqual(p.returncode, 1)
        self.assertEqual(p.stdout, "no matches\n")

    def test_grep_single_file_groups_under_no_path(self):
        self._write(
            "f.txt",
            "\n".join("match line %03d" % i for i in range(100)) + "\n",
        )
        p = self.run_actx("grep", "match", "f.txt")
        self.assertEqual(p.returncode, 0)
        self.assertIn("(no path): 100 matches", p.stdout)
        self.assertIn("match line 000", p.stdout)


if __name__ == "__main__":
    unittest.main()
