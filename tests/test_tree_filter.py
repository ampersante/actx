import json
import os
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACTX = os.path.join(ROOT, "actx")


class TreeFilterTests(unittest.TestCase):
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

    def _write(self, relpath, content=""):
        path = os.path.join(self.work.name, relpath)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
        return path

    def _write_config(self, config):
        path = os.path.join(self.home.name, ".config", "actx", "config.json")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(config, handle)

    def test_default_ignores_applied(self):
        self._write("node_modules/pkg/file.js", "x")
        self._write("target/debug/out.bin", "x")
        self._write("yarn.lock", "x")
        self._write("src/main.py", "x")
        self._write("src/utils.py", "x")
        self._write("src/lib/a.py", "x")
        self._write("tests/test_a.py", "x")
        p = self.run_actx("tree")
        self.assertEqual(p.returncode, 0)
        self.assertNotIn("node_modules", p.stdout)
        self.assertNotIn("target", p.stdout)
        self.assertNotIn("yarn.lock", p.stdout)
        self.assertIn("src", p.stdout)
        self.assertIn("main.py", p.stdout)
        self.assertIn("lib", p.stdout)

    def test_custom_ignore_config_respected(self):
        self._write("vendor/pkg/file.js", "x")
        self._write("keep.txt", "x")
        self._write_config({"ignore_dirs": ["vendor"], "ignore_files": ["*.tmp"]})
        self._write("drop.tmp", "x")
        p = self.run_actx("tree")
        self.assertEqual(p.returncode, 0)
        self.assertNotIn("vendor", p.stdout)
        self.assertNotIn("drop.tmp", p.stdout)
        self.assertIn("keep.txt", p.stdout)

    def test_large_tree_has_truncation_marker(self):
        for index in range(205):
            self._write("many/file_%03d.txt" % index, "x")
        p = self.run_actx("tree")
        self.assertEqual(p.returncode, 0)
        self.assertIn("... (", p.stdout)
        self.assertIn("more)", p.stdout)
        self.assertEqual(len(p.stdout.strip().split("\n")), 200)

    def test_malformed_ignore_files_do_not_crash(self):
        self._write("keep.txt", "x")
        self._write_config({"ignore_files": ["*.tmp", 3]})
        p = self.run_actx("tree")
        self.assertEqual(p.returncode, 0)
        self.assertIn("keep.txt", p.stdout)

    def test_missing_path_returns_nonzero(self):
        p = self.run_actx("tree", "does-not-exist")
        self.assertNotEqual(p.returncode, 0)


if __name__ == "__main__":
    unittest.main()
