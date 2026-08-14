import json
import os
import tempfile
import unittest

from actx_lib import config


class ConfigTests(unittest.TestCase):
    def test_created_with_defaults_on_first_run(self):
        with tempfile.TemporaryDirectory() as home:
            os.environ["HOME"] = home
            try:
                loaded = config.load()
                self.assertEqual(loaded["tee"]["enabled"], True)
                self.assertEqual(loaded["tee"]["mode"], "failures")
                self.assertEqual(loaded["truncate"]["max_lines"], 500)
                self.assertEqual(loaded["truncate"]["max_line_chars"], 300)
                path = os.path.join(home, ".config", "actx", "config.json")
                self.assertTrue(os.path.exists(path))
                with open(path, encoding="utf-8") as handle:
                    on_disk = json.load(handle)
                self.assertEqual(on_disk, loaded)
            finally:
                del os.environ["HOME"]


if __name__ == "__main__":
    unittest.main()
