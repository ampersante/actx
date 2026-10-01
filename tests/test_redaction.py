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

TEE_ALWAYS_CONFIG = {
    "tee": {"enabled": True, "mode": "always", "dir": "~/.local/share/actx/tee"},
    "truncate": {"max_lines": 500, "max_line_chars": 300},
}


class _BufferSink:
    """stdout/stderr replacement exposing .buffer for bytes writes."""

    def __init__(self):
        self.buffer = io.BytesIO()


M = redaction.MASK


class PatternTests(unittest.TestCase):
    def test_widened_patterns_match(self):
        # TK-61 C1: every literal stays secret-bearing; the value is masked
        # and the key/line kept (was: the whole line dropped).
        for text, expected in (
            ("api_key=abc123", "api_key=" + M),
            ("apikey: abc123", "apikey: " + M),
            ("API_KEY=sk-123", "API_KEY=" + M),
            ("AWS_API_KEY=sk-123", "AWS_API_KEY=" + M),
            ("private_key=-----BEGIN", "private_key=" + M),
            ("client_secret=x", "client_secret=" + M),
            ("signing_key=x", "signing_key=" + M),
            ("passphrase=x", "passphrase=" + M),
            ("AccessKey=x", "AccessKey=" + M),
        ):
            self.assertTrue(redaction.secret_bearing(text), text)
            self.assertEqual(redaction.redact_text(text), expected)

    def test_plain_words_do_not_match(self):
        for text in ("monkey business", "keyboard layout", "the keyring of life"):
            self.assertFalse(redaction.secret_bearing(text), text)
            self.assertEqual(redaction.redact_text(text), text)


class RedactTextTests(unittest.TestCase):
    def test_masks_secret_value_keeps_every_line(self):
        text = "API_KEY=sk-123\nnormal line\nanother\n"
        self.assertEqual(
            redaction.redact_text(text), "API_KEY=%s\nnormal line\nanother\n" % M
        )

    def test_empty_and_none_pass_through(self):
        self.assertEqual(redaction.redact_text(""), "")
        self.assertIsNone(redaction.redact_text(None))

    def test_fail_open_returns_input_on_error(self):
        text = "API_KEY=sk-123\nnormal\n"
        with mock.patch.object(
            redaction, "_mask", side_effect=RuntimeError("boom")
        ):
            self.assertEqual(redaction.redact_text(text), text)


class SecretBearingTests(unittest.TestCase):
    def test_json_key_line_is_secret_bearing(self):
        self.assertTrue(redaction.secret_bearing('{"api_key": "z"}'))

    def test_plain_output_is_not_secret_bearing(self):
        self.assertFalse(redaction.secret_bearing("hello world\nsecond line"))

    def test_fail_open_true_on_error(self):
        with mock.patch.object(redaction, "_mask", side_effect=RuntimeError("boom")):
            self.assertTrue(redaction.secret_bearing("anything"))


class JsonValueMaskingTests(unittest.TestCase):
    # TK-61 C1: redact_json (key drop) is gone; JSON text is value-masked
    # by redact_text and stays valid JSON with every key kept.
    def test_masks_secret_values_keeps_keys(self):
        text = '{"api_key": "x", "name": "y", "nested": {"client_secret": "s", "keep": 1}}'
        self.assertEqual(
            redaction.redact_text(text),
            '{"api_key": "%s", "name": "y", "nested": {"client_secret": "%s", "keep": 1}}'
            % (M, M),
        )

    def test_lists_are_walked(self):
        self.assertEqual(
            redaction.redact_text('[{"password": "p"}, {"a": 1}]'),
            '[{"password": "%s"}, {"a": 1}]' % M,
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
        # TK-61 C1: same masking on screen and in tee - value masked, key kept.
        self.assertEqual(out.getvalue(), "API_KEY=%s\nnormal line\n" % M)
        tee_files = os.listdir(self._tee_dir())
        self.assertEqual(len(tee_files), 1)
        with open(os.path.join(self._tee_dir(), tee_files[0]), encoding="utf-8") as handle:
            record = json.load(handle)
        self.assertEqual(record["stdout"], "API_KEY=%s\nnormal line\n" % M)
        self.assertNotIn("sk-abc123", json.dumps(record))

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
        # TK-61 C1: the value is masked, the key stays.
        self.assertIn('{"api_key": "%s"}' % M, out.getvalue())
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
        # TK-61: passthrough masks the value too (secrets always masked).
        self.assertEqual(
            out_sink.buffer.getvalue(), ("client_secret=" + M + "\n").encode()
        )


if __name__ == "__main__":
    unittest.main()
