import json
import os
import tempfile
import unittest

from actx_lib import config


class ConfigTests(unittest.TestCase):
    def setUp(self):
        # HOME hygiene (S/R1): these tests point HOME at a temp dir; save the
        # original and restore it afterwards so later tests in the same
        # process see the real environment (previously HOME was deleted).
        self._orig_home = os.environ.get("HOME")

    def tearDown(self):
        if self._orig_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = self._orig_home

    def test_created_with_defaults_on_first_run(self):
        with tempfile.TemporaryDirectory() as home:
            os.environ["HOME"] = home
            loaded = config.load()
            self.assertEqual(loaded["tee"]["enabled"], True)
            self.assertEqual(loaded["tee"]["mode"], "failures")
            self.assertEqual(loaded["truncate"]["max_lines"], 500)
            self.assertEqual(loaded["truncate"]["max_line_chars"], 300)
            self.assertEqual(loaded["bypass_commands"], [])
            self.assertEqual(loaded["tracking"]["enabled"], True)
            self.assertEqual(loaded["tracking"]["history_days"], 90)
            path = os.path.join(home, ".config", "actx", "config.json")
            self.assertTrue(os.path.exists(path))
            with open(path, encoding="utf-8") as handle:
                on_disk = json.load(handle)
            self.assertEqual(on_disk, loaded)

    def test_unknown_top_level_key_survives_load_save(self):
        with tempfile.TemporaryDirectory() as home:
            os.environ["HOME"] = home
            path = os.path.join(home, ".config", "actx", "config.json")
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as handle:
                json.dump({"extra": 1, "tee": {"enabled": False}}, handle)
            loaded = config.load()
            config.save(loaded)
            reloaded = config.load()
            self.assertEqual(reloaded["extra"], 1)
            self.assertEqual(reloaded["tee"]["enabled"], False)


if __name__ == "__main__":
    unittest.main()
