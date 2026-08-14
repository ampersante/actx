import os
import shutil
import stat
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INSTALL = os.path.join(ROOT, "install.sh")


class InstallScriptTests(unittest.TestCase):
    def _base_env(self, home, path=None):
        env = os.environ.copy()
        env["HOME"] = home
        env["ACTX_INIT"] = "0"
        env["PYTHON"] = shutil.which("python3")
        if path is not None:
            env["PATH"] = path
        return env

    def _run_install(self, env, *args):
        return subprocess.run(
            ["bash", INSTALL] + list(args),
            capture_output=True,
            text=True,
            cwd=ROOT,
            env=env,
        )

    def test_install_is_idempotent_and_symlinks_entrypoint(self):
        with tempfile.TemporaryDirectory() as home:
            env = self._base_env(home)
            for _ in range(2):
                p = self._run_install(env)
                self.assertEqual(p.returncode, 0, p.stderr)
            link = os.path.join(home, ".local", "bin", "actx")
            self.assertTrue(os.path.islink(link))
            self.assertEqual(os.readlink(link), os.path.join(ROOT, "actx"))
            p = subprocess.run(
                [link, "--version"], capture_output=True, text=True, env=env
            )
            self.assertEqual(p.returncode, 0)
            self.assertIn("actx", p.stdout)

    def test_warns_when_bin_dir_not_on_path(self):
        with tempfile.TemporaryDirectory() as home:
            env = self._base_env(home, path="/usr/bin:/bin")
            p = self._run_install(env)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn("is not on PATH", p.stderr)
            self.assertTrue(
                os.path.islink(os.path.join(home, ".local", "bin", "actx"))
            )

    def test_no_warning_when_bin_dir_on_path(self):
        with tempfile.TemporaryDirectory() as home:
            bin_dir = os.path.join(home, ".local", "bin")
            env = self._base_env(home, path=bin_dir + ":/usr/bin:/bin")
            p = self._run_install(env)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertNotIn("is not on PATH", p.stderr)

    def test_wrong_python_version_fails_before_install(self):
        with tempfile.TemporaryDirectory() as home:
            fake_bin = os.path.join(home, "fakebin")
            os.makedirs(fake_bin, exist_ok=True)
            fake_python = os.path.join(fake_bin, "python3")
            with open(fake_python, "w", encoding="utf-8") as handle:
                handle.write("#!/usr/bin/env bash\nif [[ \"$1\" == \"-c\" ]]; then echo 3.12; else echo 3.12; fi\n")
            os.chmod(fake_python, os.stat(fake_python).st_mode | stat.S_IEXEC)
            env = self._base_env(home, path=fake_bin + ":/usr/bin:/bin")
            env["PYTHON"] = fake_python
            p = self._run_install(env)
            self.assertEqual(p.returncode, 1)
            self.assertIn("3.14", p.stderr)
            self.assertFalse(
                os.path.lexists(os.path.join(home, ".local", "bin", "actx"))
            )

    def test_shell_configs_untouched(self):
        with tempfile.TemporaryDirectory() as home:
            env = self._base_env(home, path="/usr/bin:/bin")
            p = self._run_install(env)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertFalse(os.path.exists(os.path.join(home, ".zshrc")))
            self.assertFalse(os.path.exists(os.path.join(home, ".bashrc")))
            created = []
            for root, dirs, files in os.walk(home):
                dirs[:] = [d for d in dirs if d != "__pycache__"]
                for name in files:
                    created.append(os.path.relpath(os.path.join(root, name), home))
            self.assertEqual(created, [os.path.join(".local", "bin", "actx")])

    def test_help_exits_before_install(self):
        with tempfile.TemporaryDirectory() as home:
            env = self._base_env(home)
            p = self._run_install(env, "--help")
            self.assertEqual(p.returncode, 0)
            self.assertIn("usage:", p.stdout)
            self.assertFalse(
                os.path.lexists(os.path.join(home, ".local", "bin", "actx"))
            )

    def test_homebrew_formula_references_entrypoint(self):
        formula_path = os.path.join(ROOT, "packaging", "homebrew", "actx.rb")
        self.assertTrue(os.path.exists(formula_path))
        with open(formula_path, encoding="utf-8") as handle:
            formula = handle.read()
        self.assertIn('libexec.install "actx"', formula)
        self.assertIn('bin.install_symlink libexec/"actx"', formula)
        self.assertIn('depends_on "python@3.14"', formula)
        self.assertNotIn("depends_on", formula.replace('depends_on "python@3.14"', ""))


if __name__ == "__main__":
    unittest.main()
