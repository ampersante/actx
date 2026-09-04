import io
import json
import os
import sqlite3
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from actx_lib import redaction, runner

CONFIG = {
    "tee": {"enabled": False, "mode": "failures", "dir": "~/.local/share/actx/tee"},
    "truncate": {"max_lines": 500, "max_line_chars": 300},
}

# The secret is the LAST key on purpose: dropping its line (line-drop
# masking) leaves a trailing comma and breaks the JSON, while dropping the
# key (redact_json) keeps it valid.
MULTILINE_JSON = """\
{
  "UserId": "AIDAEXAMPLE",
  "account_name": "prod",
  "Roles": ["r1", "r2", "r3"],
  "SecretAccessKey": "shhh"
}
"""


class GenericRunJsonAutoDetectTests(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.TemporaryDirectory()
        os.environ["HOME"] = self.home.name
        os.environ.pop("ACTX_TRACKING", None)

    def tearDown(self):
        os.environ.pop("ACTX_TRACKING", None)
        del os.environ["HOME"]
        self.home.cleanup()

    def _run(self, result, config=CONFIG):
        out = io.StringIO()
        err = io.StringIO()
        with mock.patch("actx_lib.runner.subprocess.run", return_value=result):
            with redirect_stdout(out), redirect_stderr(err):
                rc = runner.run(["tool", "get"], config)
        return rc, out.getvalue(), err.getvalue()

    def _command_text(self):
        path = os.path.join(
            self.home.name, ".local", "share", "actx", "history.db"
        )
        conn = sqlite3.connect(path)
        try:
            return [row[0] for row in conn.execute("SELECT command_text FROM calls")]
        finally:
            conn.close()

    def _tracking_row(self):
        path = os.path.join(
            self.home.name, ".local", "share", "actx", "history.db"
        )
        conn = sqlite3.connect(path)
        try:
            return list(conn.execute("SELECT bytes_before, bytes_after FROM calls"))
        finally:
            conn.close()

    def test_multiline_json_compacted_with_secret_keys_dropped(self):
        rc, out, err = self._run(
            subprocess.CompletedProcess(["tool", "get"], 0, MULTILINE_JSON, "")
        )
        self.assertEqual(rc, 0)
        self.assertNotIn("SecretAccessKey", out)
        self.assertNotIn("shhh", out)
        obj = json.loads(out)
        self.assertEqual(
            obj, {"UserId": "AIDAEXAMPLE", "account_name": "prod",
                  "Roles": ["r1", "r2", "r3"]}
        )
        self.assertIn("Roles", out)

    def test_line_drop_breaks_json_on_line_path_control(self):
        # Control for the test above: the same payload with the secret key
        # already stripped fails json.loads (trailing comma), so run() takes
        # the line path — and its surviving output is no longer valid JSON.
        # The JSON path exists precisely to avoid this.
        text = "\n".join(MULTILINE_JSON.strip().splitlines()[:-1]) + "\n"
        rc, out, err = self._run(
            subprocess.CompletedProcess(["tool", "get"], 0, text, "")
        )
        self.assertEqual(rc, 0)
        self.assertNotIn("SecretAccessKey", out)
        with self.assertRaises(json.JSONDecodeError):
            json.loads(out)

    def test_long_json_array_trimmed_head_tail(self):
        text = json.dumps([{"id": i} for i in range(100)])
        rc, out, err = self._run(
            subprocess.CompletedProcess(["tool", "get"], 0, text, "")
        )
        self.assertEqual(rc, 0)
        obj = json.loads(out)
        self.assertEqual(len(obj), 21)
        self.assertEqual(obj[0], {"id": 0})
        self.assertEqual(obj[-1], {"id": 99})
        self.assertEqual(obj[10], "... [80 items omitted]")

    def test_invalid_json_stays_on_line_path(self):
        text = '{"a": 1,\nbroken\n[1, 2\n'
        rc, out, err = self._run(
            subprocess.CompletedProcess(["tool", "get"], 0, text, "")
        )
        self.assertEqual(rc, 0)
        self.assertEqual(out, text)
        self.assertNotIn("omitted", out)

    def test_oversized_stdout_stays_on_line_path(self):
        # >2MB of many short lines: the line path prints, caps and
        # line-truncates it — never the compacted JSON dump.
        text = (
            "{\n"
            + ",\n".join(
                ' "k%06d": "%s"' % (i, "x" * 100) for i in range(20000)
            )
            + "\n}"
        )
        self.assertGreater(len(text), 2 * 1024 * 1024)
        rc, out, err = self._run(
            subprocess.CompletedProcess(["tool", "get"], 0, text, "")
        )
        self.assertEqual(rc, 0)
        self.assertIn("lines omitted", out)
        self.assertNotIn("items omitted", out)

    def test_scalar_leading_brace_but_invalid_is_untouched(self):
        text = "{not json at all\n"
        rc, out, err = self._run(
            subprocess.CompletedProcess(["tool", "get"], 0, text, "")
        )
        self.assertEqual(rc, 0)
        self.assertEqual(out, text)

    def test_leading_whitespace_json_still_detected(self):
        text = '  \n{"name": "ok"}\n'
        rc, out, err = self._run(
            subprocess.CompletedProcess(["tool", "get"], 0, text, "")
        )
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out), {"name": "ok"})

    def test_exit_code_and_stderr_marker_preserved(self):
        rc, out, err = self._run(
            subprocess.CompletedProcess(
                ["tool", "get"], 3, '{"name": "ok"}', "warn: stale\n"
            )
        )
        self.assertEqual(rc, 3)
        self.assertEqual(json.loads(out), {"name": "ok"})
        self.assertIn("warn: stale", err)
        self.assertIn("[exit: 3]", err)

    def test_stderr_secret_line_masked_json_stdout_kept_whole(self):
        rc, out, err = self._run(
            subprocess.CompletedProcess(
                ["tool", "get"], 0, MULTILINE_JSON, "api_key=sk-9\nwarn\n"
            )
        )
        self.assertEqual(rc, 0)
        self.assertNotIn("api_key", err)
        self.assertIn("warn", err)
        self.assertIn("Roles", out)
        self.assertNotIn("shhh", out)
        json.loads(out)  # JSON not broken by line-drop

    def test_user_filter_applies_to_json_output(self):
        rules = [{"match_command": "tool", "strip_lines_matching": "prod"}]
        with mock.patch("actx_lib.user_filter.load", return_value=rules):
            rc, out, err = self._run(
                subprocess.CompletedProcess(["tool", "get"], 0, MULTILINE_JSON, "")
            )
        self.assertEqual(rc, 0)
        self.assertNotIn("prod", out)
        json.loads(out)

    def test_json_path_error_fails_open_to_line_path(self):
        result = subprocess.CompletedProcess(["tool", "get"], 0, MULTILINE_JSON, "")
        rc, out, err = self._run_with_patch(
            result, "actx_lib.runner._run_json_path", side_effect=RuntimeError("boom")
        )
        self.assertEqual(rc, 0)
        # Line path output: TK-36 line-drop masks the secret line.
        self.assertNotIn("SecretAccessKey", out)
        self.assertIn("prod", out)

    def test_compactor_failure_falls_back_to_line_path(self):
        result = subprocess.CompletedProcess(["tool", "get"], 0, MULTILINE_JSON, "")
        rc, out, err = self._run_with_patch(
            result,
            "actx_lib.filters.json_compactor.compact_json",
            side_effect=RuntimeError("boom"),
        )
        self.assertEqual(rc, 0)
        self.assertNotIn("SecretAccessKey", out)
        self.assertIn("prod", out)

    def _run_with_patch(self, result, target, side_effect):
        out = io.StringIO()
        err = io.StringIO()
        with mock.patch("actx_lib.runner.subprocess.run", return_value=result):
            with mock.patch(target, side_effect=side_effect):
                with redirect_stdout(out), redirect_stderr(err):
                    rc = runner.run(["tool", "get"], CONFIG)
        return rc, out.getvalue(), err.getvalue()

    def test_tracking_records_raw_and_emitted_bytes(self):
        clean = (
            '{\n  "UserId": "AIDAEXAMPLE",\n  "account_name": "prod",\n'
            '  "Roles": ["r1", "r2", "r3"]\n}\n'
        )
        rc, out, err = self._run(
            subprocess.CompletedProcess(["tool", "get"], 0, clean, "")
        )
        rows = self._tracking_row()
        self.assertEqual(len(rows), 1)
        raw, emitted = rows[0]
        self.assertEqual(raw, len(clean.encode("utf-8")))
        self.assertEqual(emitted, len(out.encode("utf-8")))
        self.assertEqual(self._command_text(), ["tool get"])

    def test_secret_bearing_json_still_skips_command_text(self):
        self._run(subprocess.CompletedProcess(["tool", "get"], 0, MULTILINE_JSON, ""))
        self.assertEqual(self._command_text(), [""])

    def test_tee_gets_masked_json_and_masked_stderr(self):
        config = {
            "tee": {"enabled": True, "mode": "always",
                    "dir": "~/.local/share/actx/tee"},
            "truncate": {"max_lines": 500, "max_line_chars": 300},
        }
        rc, out, err = self._run(
            subprocess.CompletedProcess(
                ["tool", "get"], 0, MULTILINE_JSON, "api_key=sk-9\nwarn\n"
            ),
            config,
        )
        self.assertEqual(rc, 0)
        tee_dir = os.path.join(self.home.name, ".local", "share", "actx", "tee")
        files = os.listdir(tee_dir)
        self.assertEqual(len(files), 1)
        with open(os.path.join(tee_dir, files[0]), encoding="utf-8") as handle:
            record = json.load(handle)
        self.assertNotIn("shhh", record["stdout"])
        self.assertNotIn("api_key", record["stderr"])
        self.assertEqual(json.loads(record["stdout"])["Roles"], ["r1", "r2", "r3"])
        self.assertIn("warn", record["stderr"])


if __name__ == "__main__":
    unittest.main()
