import io
import subprocess
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from actx_lib import runner
from actx_lib.filters import read_filter, system_filter

CONFIG = {
    "tee": {"enabled": False, "mode": "failures", "dir": "~/.local/share/actx/tee"},
    "truncate": {"max_lines": 500, "max_line_chars": 300},
}


def _run_with_result(run_fn, args, result, patch_target):
    out = io.StringIO()
    err = io.StringIO()
    raiser = mock.Mock(side_effect=RuntimeError("boom"))
    with mock.patch("actx_lib.runner.execute", return_value=result), mock.patch(
        patch_target, side_effect=raiser
    ):
        with redirect_stdout(out), redirect_stderr(err):
            rc = run_fn(args, CONFIG)
    return rc, out.getvalue(), err.getvalue()


class ExistingFilterFailOpenTests(unittest.TestCase):
    def _assert_raw(self, rc, out, err, result):
        self.assertEqual(rc, result.returncode)
        self.assertEqual(out, result.stdout)
        self.assertEqual(err, result.stderr)

    def _grep_with_failure(self, patch_target, stdout, stderr):
        result = subprocess.CompletedProcess(
            ["grep", "match", "f"], 1, stdout, stderr
        )
        out = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
        err = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
        with mock.patch(
            "actx_lib.runner.subprocess.run", return_value=result
        ), mock.patch(
            patch_target, side_effect=RuntimeError("boom")
        ), mock.patch("sys.stdout", out), mock.patch("sys.stderr", err):
            rc = runner.run_content(["grep", "match", "f"], CONFIG)
        out.flush()
        err.flush()
        return rc, out.buffer.getvalue(), err.buffer.getvalue()

    def test_grep_fails_open(self):
        # TK-61 C3: grep is the content class (runner.run_content; was
        # system_filter.run_grep). Review fix (finding 3): a masking error
        # never prints raw text - secret-bearing lines are withheld, the
        # rest is kept, one marker line is appended; exit code preserved.
        marker = b"[actx] masking failed; %d lines withheld\n"
        stdout = b"raw stdout \xff\n" * 100 + b"password=hunter2\n"
        stderr = b"raw stderr\ntoken: abc\n"
        for target in ("actx_lib.runner._mask_bytes", "actx_lib.redaction._mask"):
            with self.subTest(target=target):
                rc, out, err = self._grep_with_failure(target, stdout, stderr)
                self.assertEqual(rc, 1)
                self.assertEqual(out, b"raw stdout \xff\n" * 100 + marker % 1)
                self.assertEqual(err, b"raw stderr\n" + marker % 1)

    def test_ls_fails_open(self):
        result = subprocess.CompletedProcess(
            ["ls", "-1"], 0, "raw stdout\n", "raw stderr\n"
        )
        rc, out, err = _run_with_result(
            system_filter.run_ls,
            [],
            result,
            "actx_lib.filters.system_filter.os.path.isdir",
        )
        self._assert_raw(rc, out, err, result)

    def test_find_fails_open(self):
        stdout = "raw stdout\n" * 201
        stderr = "raw stderr\n"
        result = subprocess.CompletedProcess(["find"], 0, stdout, stderr)
        rc, out, err = _run_with_result(
            system_filter.run_find,
            ["."],
            result,
            "actx_lib.filters.system_filter.os.path.split",
        )
        self._assert_raw(rc, out, err, result)

    def test_read_fails_open(self):
        result = subprocess.CompletedProcess(
            ["cat", "a.py"], 0, "raw stdout\n", "raw stderr\n"
        )
        rc, out, err = _run_with_result(
            read_filter.run,
            ["a.py", "--level", "minimal"],
            result,
            "actx_lib.filters.read_filter._is_py_comment",
        )
        self._assert_raw(rc, out, err, result)


if __name__ == "__main__":
    unittest.main()
