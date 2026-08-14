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

    def test_level_aggressive_python_keeps_signatures_drops_bodies(self):
        content = (
            "#!/usr/bin/env python3\n"
            "\"\"\"Module docstring.\"\"\"\n"
            "import os\n"
            "TOP = 1  # inline top\n"
            "# full line comment\n"
            "def foo(a):\n"
            "    body = a + 1  # inline body\n"
            "    return body\n"
            "async def bar():\n"
            "    return None\n"
            "class Baz:\n"
            "    def method(self):\n"
            "        pass\n"
            "    attr = 2\n"
            "print('done')\n"
        )
        self._write("a.py", content)
        p = self.run_actx("read", "a.py", "--level", "aggressive")
        self.assertEqual(p.returncode, 0)
        self.assertIn("#!/usr/bin/env python3", p.stdout)
        self.assertIn("def foo(a):", p.stdout)
        self.assertIn("async def bar():", p.stdout)
        self.assertIn("class Baz:", p.stdout)
        self.assertIn("def method(self):", p.stdout)
        self.assertIn("TOP = 1  # inline top", p.stdout)
        self.assertNotIn("body = a + 1", p.stdout)
        self.assertNotIn("attr = 2", p.stdout)
        self.assertNotIn("Module docstring", p.stdout)
        self.assertNotIn("# full line comment", p.stdout)

    def test_level_aggressive_rust_keeps_signatures_drops_bodies(self):
        content = (
            "//! module docs\n"
            "/* block comment */\n"
            "use std::fs;\n"
            "fn main() {\n"
            "    let x = 1;\n"
            "}\n"
            "pub fn helper() { }\n"
            "struct Point {\n"
            "    x: i32,\n"
            "}\n"
            "impl Point {\n"
            "    fn new() -> Self { Self { x: 0 } }\n"
            "}\n"
            "trait Shape {\n"
            "    fn area(&self) -> f64;\n"
            "}\n"
            "type Alias = Point;\n"
        )
        self._write("a.rs", content)
        p = self.run_actx("read", "a.rs", "--level", "aggressive")
        self.assertEqual(p.returncode, 0)
        self.assertIn("fn main() {", p.stdout)
        self.assertIn("pub fn helper() {", p.stdout)
        self.assertIn("struct Point {", p.stdout)
        self.assertIn("impl Point {", p.stdout)
        self.assertIn("trait Shape {", p.stdout)
        self.assertIn("type Alias = Point;", p.stdout)
        self.assertNotIn("let x = 1;", p.stdout)
        self.assertNotIn("x: i32,", p.stdout)
        self.assertNotIn("block comment", p.stdout)
        self.assertNotIn("module docs", p.stdout)

    def test_level_aggressive_go_keeps_signatures_drops_bodies(self):
        content = (
            "package main\n"
            "import \"fmt\"\n"
            "/* block comment */\n"
            "func main() {\n"
            "    fmt.Println(\"hi\")\n"
            "}\n"
            "type Config struct {\n"
            "    Name string\n"
            "}\n"
        )
        self._write("a.go", content)
        p = self.run_actx("read", "a.go", "--level", "aggressive")
        self.assertEqual(p.returncode, 0)
        self.assertIn("func main() {", p.stdout)
        self.assertIn("type Config struct {", p.stdout)
        self.assertNotIn("fmt.Println", p.stdout)
        self.assertNotIn("Name string", p.stdout)
        self.assertNotIn("block comment", p.stdout)

    def test_level_aggressive_typescript_keeps_signatures_drops_bodies(self):
        content = (
            "// full line comment\n"
            "/* block comment */\n"
            "import { x } from './x';\n"
            "export function greet() {\n"
            "  console.log('hi');\n"
            "}\n"
            "class User {\n"
            "  name: string;\n"
            "}\n"
            "const answer = 42; // inline kept\n"
            "interface Person { name: string }\n"
            "type ID = string;\n"
        )
        self._write("a.ts", content)
        p = self.run_actx("read", "a.ts", "--level", "aggressive")
        self.assertEqual(p.returncode, 0)
        self.assertIn("export function greet() {", p.stdout)
        self.assertIn("class User {", p.stdout)
        self.assertIn("const answer = 42; // inline kept", p.stdout)
        self.assertIn("interface Person {", p.stdout)
        self.assertIn("type ID = string;", p.stdout)
        self.assertNotIn("console.log", p.stdout)
        self.assertNotIn("name: string;", p.stdout)
        self.assertNotIn("block comment", p.stdout)
        self.assertNotIn("full line comment", p.stdout)

    def test_level_aggressive_unknown_extension_passthrough(self):
        content = "some content\n# not python\n// not c\n"
        self._write("notes.txt", content)
        p = self.run_actx("read", "notes.txt", "--level", "aggressive")
        self.assertEqual(p.returncode, 0)
        self.assertEqual(p.stdout, content)

    def test_level_aggressive_one_line_bodies_dropped(self):
        self._write("a.py", "def foo(): return 1\n")
        p = self.run_actx("read", "a.py", "--level", "aggressive")
        self.assertEqual(p.returncode, 0)
        self.assertIn("def foo():", p.stdout)
        self.assertNotIn("return 1", p.stdout)

    def test_level_aggressive_c_like_one_line_body_dropped(self):
        self._write("a.rs", "fn main() { let x = 1; }\n")
        p = self.run_actx("read", "a.rs", "--level", "aggressive")
        self.assertEqual(p.returncode, 0)
        self.assertIn("fn main() {", p.stdout)
        self.assertNotIn("let x = 1;", p.stdout)

    def test_level_aggressive_block_comment_after_code_removed(self):
        content = (
            "const x = 1; /* start\n"
            "spanning */\n"
            "console.log('top');\n"
        )
        self._write("a.ts", content)
        p = self.run_actx("read", "a.ts", "--level", "aggressive")
        self.assertEqual(p.returncode, 0)
        self.assertIn("const x = 1;", p.stdout)
        self.assertIn("console.log('top');", p.stdout)
        self.assertNotIn("spanning", p.stdout)

    def test_level_aggressive_braces_in_strings_do_not_drop_code(self):
        content = 'const s = "{";\nconsole.log("top");\n'
        self._write("a.ts", content)
        p = self.run_actx("read", "a.ts", "--level", "aggressive")
        self.assertEqual(p.returncode, 0)
        self.assertIn('const s = "{";', p.stdout)
        self.assertIn('console.log("top");', p.stdout)

    def test_level_aggressive_rust_qualifiers_kept(self):
        content = (
            "pub const unsafe fn foo() { }\n"
            "pub(crate) fn bar() { }\n"
        )
        self._write("a.rs", content)
        p = self.run_actx("read", "a.rs", "--level", "aggressive")
        self.assertEqual(p.returncode, 0)
        self.assertIn("pub const unsafe fn foo() {", p.stdout)
        self.assertIn("pub(crate) fn bar() {", p.stdout)

    def test_level_aggressive_binary_fails_open_to_raw_bytes(self):
        content = b"x = 1\n\xff\xfe\n"
        path = os.path.join(self.work.name, "bin.py")
        with open(path, "wb") as handle:
            handle.write(content)
        env = os.environ.copy()
        env["HOME"] = self.home.name
        p = subprocess.run(
            [ACTX, "read", "bin.py", "--level", "aggressive"],
            capture_output=True,
            cwd=self.work.name,
            env=env,
        )
        self.assertEqual(p.returncode, 0)
        self.assertEqual(p.stdout, content)

    def test_missing_file_returns_cat_exit_code(self):
        p = self.run_actx("read", "missing.txt")
        self.assertEqual(p.returncode, 1)


if __name__ == "__main__":
    unittest.main()
