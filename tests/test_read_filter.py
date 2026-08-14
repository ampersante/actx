import os
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACTX = os.path.join(ROOT, "actx")


class ReadFilterTests(unittest.TestCase):
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

    def _write(self, name, content):
        path = os.path.join(self.work.name, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
        return path

    def test_level_none_passthrough(self):
        content = "#!/usr/bin/env python3\nprint('hi')\n"
        self._write("a.py", content)
        p = self.run_actx("read", "a.py")
        self.assertEqual(p.returncode, 0)
        self.assertEqual(p.stdout, content)

    def test_level_minimal_python_drops_full_line_comments(self):
        content = (
            "#!/usr/bin/env python3\n"
            "# full line comment\n"
            "x = 1  # inline\n"
            "# another full comment\n"
            "print(x)\n"
        )
        self._write("a.py", content)
        p = self.run_actx("read", "a.py", "--level", "minimal")
        self.assertEqual(p.returncode, 0)
        self.assertIn("#!/usr/bin/env python3", p.stdout)
        self.assertIn("x = 1  # inline", p.stdout)
        self.assertIn("print(x)", p.stdout)
        self.assertNotIn("# full line comment", p.stdout)
        self.assertNotIn("# another full comment", p.stdout)

    def test_level_minimal_unknown_extension_passthrough(self):
        content = "# not python\n// not c-like either\n"
        self._write("notes.txt", content)
        p = self.run_actx("read", "notes.txt", "--level", "minimal")
        self.assertEqual(p.returncode, 0)
        self.assertEqual(p.stdout, content)

    def test_level_minimal_c_like_drops_double_slash_comments(self):
        content = "int x = 1; // inline\n// full line\nint y = 2;\n"
        self._write("a.c", content)
        p = self.run_actx("read", "a.c", "--level", "minimal")
        self.assertEqual(p.returncode, 0)
        self.assertIn("int x = 1; // inline", p.stdout)
        self.assertIn("int y = 2;", p.stdout)
        self.assertNotIn("// full line", p.stdout)

    def test_level_aggressive_exit_1(self):
        self._write("a.py", "x = 1\n")
        p = self.run_actx("read", "a.py", "--level", "aggressive")
        self.assertEqual(p.returncode, 1)
        self.assertNotEqual(p.stderr, "")

    def test_missing_file_returns_cat_exit_code(self):
        p = self.run_actx("read", "missing.txt")
        self.assertEqual(p.returncode, 1)


if __name__ == "__main__":
    unittest.main()
