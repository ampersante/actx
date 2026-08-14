import json
import os
import stat
import subprocess
import tempfile
import unittest

from actx_lib import user_filter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACTX = os.path.join(ROOT, "actx")


class UserFilterTests(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.TemporaryDirectory()
        self.work = tempfile.TemporaryDirectory()
        self._write_mytool()

    def tearDown(self):
        self.home.cleanup()
        self.work.cleanup()

    def _write_mytool(self):
        path = os.path.join(self.work.name, "my-tool")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("#!/usr/bin/env python3\nprint('dup')\nprint('dup')\nprint('keep')\n")
        os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)

    def _write_filters(self, rules):
        path = os.path.join(self.home.name, ".config", "actx", "filters.json")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(rules, handle)
        return path

    def run_actx(self, *args):
        env = os.environ.copy()
        env["HOME"] = self.home.name
        env["PATH"] = self.work.name + os.pathsep + env.get("PATH", "")
        return subprocess.run(
            [ACTX] + list(args),
            capture_output=True,
            text=True,
            cwd=self.work.name,
            env=env,
        )

    def test_dedupe_lines_on_run_command(self):
        self._write_filters([{"match_command": "my-tool", "dedupe_lines": True}])
        p = self.run_actx("run", "my-tool")
        self.assertEqual(p.returncode, 0)
        self.assertEqual(p.stdout, "dup\nkeep\n")

    def test_unknown_key_prints_error_and_leaves_file(self):
        path = self._write_filters([{"match_command": "my-tool", "bogus": 1}])
        with open(path, encoding="utf-8") as handle:
            before = handle.read()
        p = self.run_actx("run", "my-tool")
        self.assertEqual(p.returncode, 0)
        self.assertIn("unknown filters.json key(s): bogus", p.stderr)
        self.assertIn("dup", p.stdout)
        with open(path, encoding="utf-8") as handle:
            self.assertEqual(handle.read(), before)

    def test_invalid_rule_fails_open_to_raw_output(self):
        self._write_filters([{"match_command": "my-tool", "max_lines": "abc"}])
        p = self.run_actx("run", "my-tool")
        self.assertEqual(p.returncode, 0)
        self.assertEqual(p.stdout, "dup\ndup\nkeep\n")
        self.assertNotIn("Traceback", p.stderr)

    def test_apply_supported_keys(self):
        text = "\x1b[31mred\x1b[0m\naa\nbb\naa\ncc\n"
        rules = [
            {"strip_ansi": True},
            {"dedupe_lines": True},
            {"max_lines": 2},
        ]
        self.assertEqual(user_filter.apply(rules, "any", text), "red\naa")

    def test_apply_replace(self):
        rules = [{"replace": {"pattern": "foo", "replacement": "bar"}}]
        self.assertEqual(user_filter.apply(rules, "any", "foo\nfood"), "bar\nbard")


if __name__ == "__main__":
    unittest.main()
