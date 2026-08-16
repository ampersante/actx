import os
import subprocess
import tempfile
import unittest

from actx_lib import runner

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACTX = os.path.join(ROOT, "actx")


class LosslessTransformTests(unittest.TestCase):
    def test_collapse_consecutive_identical(self):
        self.assertEqual(runner._collapse_lines("a\na\na\n"), "a  [×3]\n")

    def test_collapse_preserves_non_consecutive(self):
        self.assertEqual(runner._collapse_lines("a\nb\na\n"), "a\nb\na\n")

    def test_collapse_skips_empty_lines(self):
        self.assertEqual(runner._collapse_lines("a\n\n\na\n"), "a\n\n\na\n")

    def test_strip_ansi(self):
        self.assertEqual(runner._strip_ansi("\x1b[31mred\x1b[0m"), "red")

    def test_cap_explicit_head_tail(self):
        text = "\n".join(str(i) for i in range(10)) + "\n"
        out = runner._cap_lines_explicit(text, 4, 300)
        self.assertIn("0", out)
        self.assertIn("9", out)
        self.assertIn("6 lines omitted", out)


class LosslessCliTests(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.TemporaryDirectory()
        self.work = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.home.cleanup()
        self.work.cleanup()

    def test_sort_collapses_repeats(self):
        path = os.path.join(self.work.name, "f.txt")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("b\na\na\n")
        env = {**os.environ, "HOME": self.home.name}
        p = subprocess.run(
            [ACTX, "sort", "f.txt"],
            capture_output=True,
            text=True,
            cwd=self.work.name,
            env=env,
        )
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("a  [×2]", p.stdout)
        self.assertIn("b", p.stdout)


if __name__ == "__main__":
    unittest.main()
