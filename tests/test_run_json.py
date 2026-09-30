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

# The secret is the LAST key on purpose: the pre-TK-61 line-drop left a
# trailing comma there and broke the JSON; value masking (TK-61) keeps the
# key and replaces only the value, so the JSON stays valid on every path.
MASKED_SECRET = '"SecretAccessKey": "‹masked›"'
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

    def test_multiline_json_compacted_with_secret_values_masked(self):
        # TK-61 C1: the secret key stays, its value is masked (was: key
        # dropped by redact_json). TK-61 C2: JSON is printed as its masked
        # raw text (json.loads is only a predicate).
        rc, out, err = self._run(
            subprocess.CompletedProcess(["tool", "get"], 0, MULTILINE_JSON, "")
        )
        self.assertEqual(rc, 0)
        self.assertEqual(out, redaction.redact_text(MULTILINE_JSON))
        self.assertIn(MASKED_SECRET, out)
        self.assertNotIn("shhh", out)
        obj = json.loads(out)
        self.assertEqual(
            obj, {"UserId": "AIDAEXAMPLE", "account_name": "prod",
                  "Roles": ["r1", "r2", "r3"], "SecretAccessKey": "‹masked›"}
        )
        self.assertIn("Roles", out)

    def test_invalid_json_line_path_masks_value_control(self):
        # Control for the test above: the same payload without its closing
        # brace fails json.loads, so run() takes the line path; value
        # masking there keeps the key line and hides only the value
        # (TK-61 C1; was: the secret line dropped).
        text = "\n".join(MULTILINE_JSON.strip().splitlines()[:-1]) + "\n"
        rc, out, err = self._run(
            subprocess.CompletedProcess(["tool", "get"], 0, text, "")
        )
        self.assertEqual(rc, 0)
        self.assertEqual(out, text.replace('"shhh"', '"‹masked›"'))
        self.assertIn(MASKED_SECRET, out)
        with self.assertRaises(json.JSONDecodeError):
            json.loads(out)

    def test_long_json_array_printed_whole(self):
        # TK-61 C2: JSON never loses members (was: head/tail with
        # "... [80 items omitted]").
        text = json.dumps([{"id": i} for i in range(100)])
        rc, out, err = self._run(
            subprocess.CompletedProcess(["tool", "get"], 0, text, "")
        )
        self.assertEqual(rc, 0)
        self.assertEqual(out, text + "\n")

    def test_invalid_json_stays_on_line_path(self):
        text = '{"a": 1,\nbroken\n[1, 2\n'
        rc, out, err = self._run(
            subprocess.CompletedProcess(["tool", "get"], 0, text, "")
        )
        self.assertEqual(rc, 0)
        self.assertEqual(out, text)
        self.assertNotIn("omitted", out)

    def test_oversized_json_printed_whole(self):
        # TK-61 C2: no size limit on the JSON predicate — >2MB of valid JSON
        # is printed whole, never line-capped (was: the line path capped it
        # with "lines omitted").
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
        self.assertEqual(out, text + "\n")
        self.assertNotIn("full output", err)

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
        self.assertIn("api_key=‹masked›\n", err)  # TK-61: value masked, key kept
        self.assertNotIn("sk-9", err)
        self.assertIn("warn", err)
        self.assertIn("Roles", out)
        self.assertNotIn("shhh", out)
        json.loads(out)  # JSON not broken by masking

    def test_user_filter_applies_to_json_output(self):
        rules = [{"match_command": "tool", "strip_lines_matching": "prod"}]
        with mock.patch("actx_lib.user_filter.load", return_value=rules):
            rc, out, err = self._run(
                subprocess.CompletedProcess(["tool", "get"], 0, MULTILINE_JSON, "")
            )
        self.assertEqual(rc, 0)
        self.assertNotIn("prod", out)
        json.loads(out)

    def test_json_path_single_auth_hint_on_failing_exit(self):
        # G4b (single emission): one hint for JSON stdout on a failing exit.
        result = subprocess.CompletedProcess(
            ["tool", "get"], 1, '{"name": "ok"}',
            "ERROR: 401 Unauthorized — not logged in\n",
        )
        rc, out, err = self._run(result)
        self.assertEqual(rc, 1)
        self.assertEqual(json.loads(out), {"name": "ok"})
        self.assertEqual(err.count("[actx] hint:"), 1)
        self.assertIn("hint: auth error", err)

    def test_session_hints_error_fails_open_on_all_paths(self):
        # G6: a raising _session_hints must not distort output/exit on the
        # runner paths (run, errors, digest, compacted).
        sample = subprocess.CompletedProcess(
            ["tool", "get"], 1, 'plain output\n',
            "ERROR: 401 Unauthorized — not logged in\n",
        )

        def broken(result):
            raise RuntimeError("boom")

        with mock.patch("actx_lib.runner._session_hints", side_effect=broken):
            rc, out, err = self._run(sample)
            self.assertEqual(rc, 1)
            # TK-61 C2: stdout survives a failing exit (was: stderr only).
            self.assertEqual(out, "plain output\n")
            self.assertNotIn("[actx] hint:", err)
            self.assertIn("[exit: 1]", err)

        with mock.patch("actx_lib.runner._session_hints", side_effect=broken):
            out_e, err_e = io.StringIO(), io.StringIO()
            with redirect_stdout(out_e), redirect_stderr(err_e):
                rc_e = runner.run_errors(["tool", "get"])
            self.assertEqual(rc_e, 1)

        with mock.patch("actx_lib.runner._session_hints", side_effect=broken):
            out_d, err_d = io.StringIO(), io.StringIO()
            with redirect_stdout(out_d), redirect_stderr(err_d):
                rc_d = runner.run_digest(["tool", "get"])
            self.assertEqual(rc_d, 1)

        with mock.patch("actx_lib.runner.subprocess.run", return_value=sample):
            with mock.patch("actx_lib.runner._session_hints", side_effect=broken):
                out_c, err_c = io.StringIO(), io.StringIO()
                with redirect_stdout(out_c), redirect_stderr(err_c):
                    rc_c = runner.compacted_result(
                        ["tool", "get"], sample, CONFIG,
                        runner.stdout_compactor(lambda text: text),
                    )
                self.assertEqual(rc_c, 1)
                self.assertNotIn("[actx] hint:", err_c.getvalue())
                self.assertIn("plain output", out_c.getvalue())

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
        self.assertIn(MASKED_SECRET, record["stdout"])
        self.assertIn("api_key=‹masked›\n", record["stderr"])
        self.assertNotIn("sk-9", record["stderr"])
        self.assertEqual(json.loads(record["stdout"])["Roles"], ["r1", "r2", "r3"])
        self.assertIn("warn", record["stderr"])


if __name__ == "__main__":
    unittest.main()
