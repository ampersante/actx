import json
import time
import unittest
from unittest import mock

from actx_lib.filters import json_compactor


def _list_json(count, inner_key="name"):
    items = [{"id": i, inner_key: "row %d" % i} for i in range(count)]
    return json.dumps(items)


class CompactJsonTests(unittest.TestCase):
    def test_valid_object_compacts(self):
        out = json_compactor.compact_json('{"a": 1, "b": "x"}')
        self.assertEqual(json.loads(out), {"a": 1, "b": "x"})
        self.assertEqual(out, '{"a": 1, "b": "x"}')

    def test_valid_array_compacts(self):
        out = json_compactor.compact_json('[1, 2, 3]')
        self.assertEqual(json.loads(out), [1, 2, 3])

    def test_secret_keys_dropped_before_trimming(self):
        text = (
            '[{"api_key": "x", "name": "y"}, {"api_key": "z", "name": "w"},'
            ' {"name": "v"}]'
        )
        out = json_compactor.compact_json(text, max_items=2)
        self.assertNotIn("api_key", out)
        self.assertNotIn('"x"', out)
        self.assertNotIn('"z"', out)
        obj = json.loads(out)
        self.assertEqual(obj, [{"name": "y"}, "... [1 items omitted]", {"name": "v"}])

    def test_nested_objects_and_lists(self):
        text = json.dumps({"outer": [{"inner": [{"deep": 1}]}], "n": 2})
        out = json_compactor.compact_json(text, max_items=None)
        self.assertEqual(json.loads(out), json.loads(text))

    def test_long_list_trimmed_head_tail_with_marker(self):
        out = json_compactor.compact_json(_list_json(1000), max_items=20)
        obj = json.loads(out)
        self.assertEqual(len(obj), 21)
        self.assertEqual(obj[0], {"id": 0, "name": "row 0"})
        self.assertEqual(obj[-1], {"id": 999, "name": "row 999"})
        self.assertEqual(obj[10], "... [980 items omitted]")
        for item in obj:
            if item is not obj[10]:
                self.assertIsInstance(item, dict)

    def test_nested_lists_trimmed_recursively(self):
        text = json.dumps(
            {"items": [json.loads(_list_json(100)) for _ in range(3)]}
        )
        out = json_compactor.compact_json(text, max_items=10)
        obj = json.loads(out)
        for row in obj["items"]:
            self.assertEqual(len(row), 11)
            self.assertEqual(row[5], "... [90 items omitted]")

    def test_marker_not_inserted_when_list_not_longer(self):
        out = json_compactor.compact_json(_list_json(20), max_items=20)
        self.assertEqual(json.loads(out), json.loads(_list_json(20)))
        self.assertNotIn("omitted", out)

    def test_invalid_json_returns_none(self):
        for text in ("", "   ", "not json", "{", "[1, 2", "null]"):
            self.assertIsNone(json_compactor.compact_json(text), repr(text))

    def test_scalar_is_valid_json(self):
        self.assertEqual(json_compactor.compact_json("42"), "42")
        self.assertEqual(json_compactor.compact_json('"txt"'), '"txt"')
        self.assertEqual(json_compactor.compact_json("null"), "null")
        self.assertEqual(json_compactor.compact_json("true"), "true")

    def test_max_items_none_keeps_long_list(self):
        out = json_compactor.compact_json(_list_json(1000), max_items=None)
        self.assertEqual(json.loads(out), json.loads(_list_json(1000)))
        self.assertNotIn("omitted", out)

    def test_indent_two_sort_keys_matches_legacy_dump(self):
        obj = {"b": 2, "a": {"d": 4, "c": 3}}
        text = json.dumps(obj)
        out = json_compactor.compact_json(text, indent=2, sort_keys=True, max_items=None)
        self.assertEqual(
            out, json.dumps(json.loads(text), indent=2, sort_keys=True)
        )
        self.assertIn('\n  "a"', out)

    def test_default_indent_is_compact(self):
        out = json_compactor.compact_json('{"a": [1, 2]}')
        self.assertNotIn("\n", out)

    def test_internal_error_fails_open_to_none(self):
        with mock.patch.object(
            json_compactor.redaction, "redact_json", side_effect=RuntimeError("boom")
        ):
            self.assertIsNone(json_compactor.compact_json('{"a": 1}'))

    def test_trim_lists_error_fails_open_to_none(self):
        # Any trimming bug must fail open (None), not emit broken JSON.
        with mock.patch.object(
            json_compactor, "_trim_lists", side_effect=RuntimeError("boom")
        ):
            self.assertIsNone(json_compactor.compact_json(_list_json(25), max_items=20))

    def test_perf_two_mb_json_compacts_under_2s(self):
        # PRD.md 13.10: documented 3x flake tolerance; base limit 2s.
        items = [
            {"id": i, "name": "row %d" % i, "tags": ["alpha", "beta", "gamma"]}
            for i in range(40000)
        ]
        text = json.dumps(items)
        self.assertGreater(len(text), 2 * 1024 * 1024)

        start = time.perf_counter()
        out = json_compactor.compact_json(text, max_items=20)
        elapsed = time.perf_counter() - start

        self.assertLess(elapsed, 2.0, "compact_json 2MB %.3fs" % elapsed)
        self.assertLess(len(out), len(text) / 100)
        obj = json.loads(out)
        self.assertEqual(len(obj), 21)
        self.assertIn("items omitted", obj[10])


if __name__ == "__main__":
    unittest.main()
