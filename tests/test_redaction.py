import io
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

TEE_ALWAYS_CONFIG = {
    "tee": {"enabled": True, "mode": "always", "dir": "~/.local/share/actx/tee"},
    "truncate": {"max_lines": 500, "max_line_chars": 300},
}


class _BufferSink:
    """stdout/stderr replacement exposing .buffer for bytes writes."""

    def __init__(self):
        self.buffer = io.BytesIO()


class PatternTests(unittest.TestCase):
    def test_widened_patterns_match(self):
        for text in (
            "api_key=abc123",
            "apikey: abc123",
            "API_KEY=sk-123",
            "AWS_API_KEY=sk-123",
            "private_key=-----BEGIN",
            "client_secret=x",
            "signing_key=x",
            "passphrase=x",
            "AccessKey=x",
        ):
            self.assertTrue(redaction.secret_bearing(text), text)
            self.assertEqual(redaction.redact_text(text), "")

    def test_plain_words_do_not_match(self):
        for text in ("monkey business", "keyboard layout", "the keyring of life"):
            self.assertFalse(redaction.secret_bearing(text), text)
            self.assertEqual(redaction.redact_text(text), text)


class RedactTextTests(unittest.TestCase):
    def test_drops_secret_line_keeps_normal_lines(self):
        text = "API_KEY=sk-123\nnormal line\nanother\n"
        self.assertEqual(redaction.redact_text(text), "normal line\nanother\n")

    def test_empty_and_none_pass_through(self):
        self.assertEqual(redaction.redact_text(""), "")
        self.assertIsNone(redaction.redact_text(None))

    def test_fail_open_returns_input_on_error(self):
        text = "API_KEY=sk-123\nnormal\n"
        with mock.patch.object(
            redaction, "_drop_secret_lines", side_effect=RuntimeError("boom")
        ):
            self.assertEqual(redaction.redact_text(text), text)


class SecretBearingTests(unittest.TestCase):
    def test_json_key_line_is_secret_bearing(self):
        self.assertTrue(redaction.secret_bearing('{"api_key": "z"}'))

    def test_plain_output_is_not_secret_bearing(self):
        self.assertFalse(redaction.secret_bearing("hello world\nsecond line"))

    def test_fail_open_true_on_error(self):
        with mock.patch.object(redaction, "_SECRET_PATTERNS", None):
            self.assertTrue(redaction.secret_bearing("anything"))


class RedactJsonTests(unittest.TestCase):
    def test_drops_secret_keys_keeps_rest(self):
        obj = {"api_key": "x", "name": "y", "nested": {"client_secret": "s", "keep": 1}}
        self.assertEqual(
            redaction.redact_json(obj), {"name": "y", "nested": {"keep": 1}}
        )

    def test_lists_are_walked(self):
        # An emptied dict stays in the list; only secret keys are dropped.
        self.assertEqual(
            redaction.redact_json([{"password": "p"}, {"a": 1}]), [{}, {"a": 1}]
        )


class GenericRunRedactionTests(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.TemporaryDirectory()
        os.environ["HOME"] = self.home.name
        os.environ.pop("ACTX_TRACKING", None)

    def tearDown(self):
        os.environ.pop("ACTX_TRACKING", None)
        del os.environ["HOME"]
        self.home.cleanup()

    def _command_text(self):
        path = os.path.join(self.home.name, ".local", "share", "actx", "history.db")
        conn = sqlite3.connect(path)
        try:
            return [row[0] for row in conn.execute("SELECT command_text FROM calls")]
        finally:
            conn.close()

    def _tee_dir(self):
        return os.path.join(self.home.name, ".local", "share", "actx", "tee")

    def test_secret_line_masked_on_screen_and_tee(self):
        out = io.StringIO()
        err = io.StringIO()
        result = subprocess.CompletedProcess(
            ["python3", "-c", "x"], 0, "API_KEY=sk-abc123\nnormal line\n", ""
        )
        with mock.patch("actx_lib.runner.subprocess.run", return_value=result):
            with redirect_stdout(out), redirect_stderr(err):
                rc = runner.run(["python3", "-c", "x"], TEE_ALWAYS_CONFIG)
        self.assertEqual(rc, 0)
        self.assertNotIn("API_KEY", out.getvalue())
        self.assertIn("normal line", out.getvalue())
        tee_files = os.listdir(self._tee_dir())
        self.assertEqual(len(tee_files), 1)
        with open(os.path.join(self._tee_dir(), tee_files[0]), encoding="utf-8") as handle:
            record = handle.read()
        self.assertNotIn("API_KEY", record)
        self.assertIn("normal line", record)

    def test_json_secret_output_masked(self):
        out = io.StringIO()
        err = io.StringIO()
        result = subprocess.CompletedProcess(
            ["python3", "-c", "x"], 0,
            '{"api_key": "z"}\n{"name": "keepme"}\n', "",
        )
        with mock.patch("actx_lib.runner.subprocess.run", return_value=result):
            with redirect_stdout(out), redirect_stderr(err):
                rc = runner.run(["python3", "-c", "x"], CONFIG)
        self.assertEqual(rc, 0)
        self.assertNotIn("api_key", out.getvalue())
        self.assertNotIn('"z"', out.getvalue())
        self.assertIn("keepme", out.getvalue())

    def test_secret_bearing_output_leaves_empty_command_text(self):
        out = io.StringIO()
        err = io.StringIO()
        result = subprocess.CompletedProcess(
            ["python3", "-c", "x"], 0, "API_KEY=sk-abc123\n", ""
        )
        with mock.patch("actx_lib.runner.subprocess.run", return_value=result):
            with redirect_stdout(out), redirect_stderr(err):
                rc = runner.run(["python3", "-c", "x"], CONFIG)
        self.assertEqual(rc, 0)
        self.assertEqual(self._command_text(), [""])

    def test_clean_output_still_stores_command_text(self):
        out = io.StringIO()
        err = io.StringIO()
        result = subprocess.CompletedProcess(
            ["python3", "-c", "x"], 0, "hello\n", ""
        )
        with mock.patch("actx_lib.runner.subprocess.run", return_value=result):
            with redirect_stdout(out), redirect_stderr(err):
                rc = runner.run(["python3", "-c", "x"], CONFIG)
        self.assertEqual(rc, 0)
        self.assertEqual(self._command_text(), ["python3 -c x"])

    def test_redaction_failure_prints_raw_no_tee_no_command_text(self):
        out = io.StringIO()
        err = io.StringIO()
        result = subprocess.CompletedProcess(
            ["python3", "-c", "x"], 0, "API_KEY=sk-abc123\n", ""
        )
        with mock.patch("actx_lib.runner.subprocess.run", return_value=result):
            with mock.patch(
                "actx_lib.runner.redaction.redact_text",
                side_effect=RuntimeError("boom"),
            ):
                with redirect_stdout(out), redirect_stderr(err):
                    rc = runner.run(["python3", "-c", "x"], TEE_ALWAYS_CONFIG)
        self.assertEqual(rc, 0)
        self.assertIn("API_KEY=sk-abc123", out.getvalue())
        self.assertFalse(os.path.exists(self._tee_dir()))
        self.assertEqual(self._command_text(), [""])

    def test_passthrough_secret_bearing_leaves_empty_command_text(self):
        result = subprocess.CompletedProcess(
            ["python3", "-c", "x"], 0, b"client_secret=hush\n", b""
        )
        out_sink = _BufferSink()
        err_sink = _BufferSink()
        with mock.patch("actx_lib.runner.subprocess.run", return_value=result):
            with redirect_stdout(out_sink), redirect_stderr(err_sink):
                rc = runner.run_passthrough(["python3", "-c", "x"])
        self.assertEqual(rc, 0)
        self.assertEqual(self._command_text(), [""])


if __name__ == "__main__":
    unittest.main()
