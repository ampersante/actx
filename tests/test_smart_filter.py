import io
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from actx_lib.filters import smart_filter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACTX = os.path.join(ROOT, "actx")

CONFIG = {
    "tee": {"enabled": False, "mode": "failures", "dir": "~/.local/share/actx/tee"},
    "truncate": {"max_lines": 500, "max_line_chars": 300},
}


class SmartFilterTests(unittest.TestCase):
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

    def test_python_summary(self):
        content = (
            "#!/usr/bin/env python3\n"
            "import os\n"
            "import sys\n"
            "from pathlib import Path\n"
            "class Alpha:\n"
            "    def a(self):\n"
            "        return 1\n"
            "    def b(self):\n"
            "        return 2\n"
            "def top():\n"
            "    return 3\n"
            "async def async_top():\n"
            "    return 4\n"
        )
        self._write("a.py", content)
        p = self.run_actx("smart", "a.py")
        self.assertEqual(p.returncode, 0)
        self.assertIn("language: python", p.stdout)
        self.assertIn("functions: 4, classes: 1", p.stdout)
        self.assertIn("imports: os, sys, pathlib", p.stdout)
        self.assertLess(len(p.stdout.encode()), len(content.encode()))

    def test_rust_summary(self):
        content = (
            "use std::collections::HashMap;\n"
            "use std::fs;\n"
            "fn main() { }\n"
            "pub fn helper() { }\n"
            "struct Point { x: i32 }\n"
            "impl Point {\n"
            "    fn new() -> Self { Point { x: 0 } }\n"
            "}\n"
            "trait Shape {\n"
            "    fn area(&self) -> f64;\n"
            "}\n"
            "type Alias = Point;\n"
        )
        self._write("a.rs", content)
        p = self.run_actx("smart", "a.rs")
        self.assertEqual(p.returncode, 0)
        self.assertIn("language: rust", p.stdout)
        self.assertIn("functions: 4, structs: 1, impls: 1, traits: 1", p.stdout)
        self.assertIn(
            "imports: std::collections::HashMap, std::fs", p.stdout
        )
        self.assertLess(len(p.stdout.encode()), len(content.encode()))

    def test_typescript_summary(self):
        content = (
            'import fs from "fs";\n'
            'import { parse } from "./parser";\n'
            "export function run() { }\n"
            "class Runner { method() { } }\n"
            "const config = {};\n"
            "interface Options { verbose: boolean }\n"
            "type ID = string;\n"
        )
        self._write("a.ts", content)
        p = self.run_actx("smart", "a.ts")
        self.assertEqual(p.returncode, 0)
        self.assertIn("language: typescript", p.stdout)
        self.assertIn("functions: 1, classes: 1, interfaces: 1, types: 1", p.stdout)
        self.assertIn('imports: fs, ./parser', p.stdout)
        self.assertLess(len(p.stdout.encode()), len(content.encode()))

    def test_rust_qualifiers_counted(self):
        content = (
            "pub const unsafe fn foo() { }\n"
            'extern "C" fn bar() { }\n'
        )
        self._write("a.rs", content)
        p = self.run_actx("smart", "a.rs")
        self.assertEqual(p.returncode, 0)
        self.assertIn("functions: 2", p.stdout)

    def test_binary_fails_open_to_raw_bytes(self):
        content = b"fn main() {}\n\xff\xfe\n"
        path = os.path.join(self.work.name, "bin.rs")
        with open(path, "wb") as handle:
            handle.write(content)
        env = os.environ.copy()
        env["HOME"] = self.home.name
        p = subprocess.run(
            [ACTX, "smart", "bin.rs"],
            capture_output=True,
            cwd=self.work.name,
            env=env,
        )
        self.assertEqual(p.returncode, 0)
        self.assertEqual(p.stdout, content)

    def test_unknown_extension_message(self):
        self._write("notes.txt", "hello\n")
        p = self.run_actx("smart", "notes.txt")
        self.assertEqual(p.returncode, 0)
        self.assertEqual(p.stdout, "unknown language\n")

    def test_missing_file_returns_cat_exit_code(self):
        p = self.run_actx("smart", "missing.py")
        self.assertEqual(p.returncode, 1)

    def test_fail_open_returns_raw_passthrough(self):
        result = subprocess.CompletedProcess(
            ["cat", "a.py"], 0, "raw stdout\n", "raw stderr\n"
        )
        out = io.StringIO()
        err = io.StringIO()
        raiser = mock.Mock(side_effect=RuntimeError("boom"))
        with mock.patch("actx_lib.runner.execute", return_value=result), mock.patch(
            "actx_lib.filters.smart_filter._summarize", side_effect=raiser
        ):
            with redirect_stdout(out), redirect_stderr(err):
                rc = smart_filter.run(["a.py"], CONFIG)
        self.assertEqual(rc, 0)
        self.assertEqual(out.getvalue(), "raw stdout\n")
        self.assertEqual(err.getvalue(), "raw stderr\n")


if __name__ == "__main__":
    unittest.main()
