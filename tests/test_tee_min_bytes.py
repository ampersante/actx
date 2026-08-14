import json
import os
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACTX = os.path.join(ROOT, "actx")


class TeeMinBytesTests(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.TemporaryDirectory()
        self.work = tempfile.TemporaryDirectory()
        self._write_config()

    def tearDown(self):
        self.home.cleanup()
        self.work.cleanup()

    def _write_config(self):
        path = os.path.join(self.home.name, ".config", "actx", "config.json")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "tee": {
                        "enabled": True,
                        "mode": "always",
                        "dir": "~/.local/share/actx/tee",
                        "min_bytes": 100,
                    }
                },
                handle,
            )

    def _tee_dir(self):
        return os.path.join(self.home.name, ".local", "share", "actx", "tee")

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

    def test_small_output_no_tee_file(self):
        p = self.run_actx("run", "python3", "-c", "print('hi')")
        self.assertEqual(p.returncode, 0)
        tee_dir = self._tee_dir()
        self.assertFalse(os.path.exists(tee_dir))

    def test_large_output_creates_tee_file(self):
        p = self.run_actx("run", "python3", "-c", "print('x' * 120)")
        self.assertEqual(p.returncode, 0)
        tee_dir = self._tee_dir()
        self.assertTrue(os.path.exists(tee_dir))
        files = [name for name in os.listdir(tee_dir) if name.endswith(".log")]
        self.assertEqual(len(files), 1)


if __name__ == "__main__":
    unittest.main()
