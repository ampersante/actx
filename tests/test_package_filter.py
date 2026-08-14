import io
import subprocess
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from actx_lib.filters import package_filter

CONFIG = {
    "tee": {"enabled": False, "mode": "failures", "dir": "~/.local/share/actx/tee"},
    "truncate": {"max_lines": 500, "max_line_chars": 300},
}

PIP_LIST = """\
Package    Version
---------- -------
requests   2.31.0
numpy      1.26.4
pip        24.0
"""

PIP_OUTDATED = """\
Package    Version Latest Type
---------- ------- ------ -----
requests   2.28.0  2.31.0 wheel
numpy      1.26.0  1.26.4 wheel
"""

UV_RUN = """\
Resolved 10 packages in 200ms
Installed 2 packages in 50ms
\u280b Preparing packages... (0/1)
hello from child
another line
"""

NPM_LIST = """\
project@1.0.0 /path
\u251c\u2500\u2500 dep-a@1.0.0
\u251c\u2500\u252c dep-b@2.0.0
\u2502 \u2514\u2500\u2500 dep-c@3.0.0
\u2514\u2500\u2500 dep-d@4.0.0
"""

PNPM_LIST = """\
Legend: production dependency, optional only, dev only

project@1.0.0 /path

dependencies:
dep-a 1.0.0
dep-b 2.0.0

devDependencies:
dep-c 3.0.0
"""


class PackageParserTests(unittest.TestCase):
    def test_pip_list_keeps_package_lines(self):
        out = package_filter.compact_pip(PIP_LIST)
        self.assertIn("requests   2.31.0", out)
        self.assertIn("numpy      1.26.4", out)
        self.assertIn("pip        24.0", out)
        self.assertNotIn("Package", out)
        self.assertNotIn("----", out)

    def test_pip_outdated_keeps_package_lines(self):
        out = package_filter.compact_pip(PIP_OUTDATED)
        self.assertIn("requests   2.28.0  2.31.0 wheel", out)
        self.assertIn("numpy      1.26.0  1.26.4 wheel", out)
        self.assertNotIn("Package", out)

    def test_uv_run_drops_install_lines(self):
        out = package_filter.compact_uv_run(UV_RUN)
        self.assertIn("hello from child", out)
        self.assertIn("another line", out)
        self.assertNotIn("Resolved", out)
        self.assertNotIn("Installed", out)
        self.assertNotIn("Preparing", out)

    def test_npm_list_keeps_package_names(self):
        out = package_filter.compact_npm_list(NPM_LIST)
        self.assertIn("dep-a@1.0.0", out)
        self.assertIn("dep-b@2.0.0", out)
        self.assertIn("dep-c@3.0.0", out)
        self.assertIn("dep-d@4.0.0", out)
        self.assertNotIn("project@1.0.0", out)

    def test_pnpm_list_keeps_package_names(self):
        out = package_filter.compact_pnpm_list(PNPM_LIST)
        self.assertIn("dependencies:", out)
        self.assertIn("dep-a 1.0.0", out)
        self.assertIn("dep-b 2.0.0", out)
        self.assertIn("devDependencies:", out)
        self.assertNotIn("Legend:", out)
        self.assertNotIn("project@1.0.0", out)


class PackageExitCodeTests(unittest.TestCase):
    def test_pip_preserves_exit_code(self):
        result = subprocess.CompletedProcess(["pip", "list"], 1, PIP_LIST, "")
        out = io.StringIO()
        err = io.StringIO()
        with mock.patch("actx_lib.runner.execute", return_value=result):
            with redirect_stdout(out), redirect_stderr(err):
                rc = package_filter.run_pip(["list"], CONFIG)
        self.assertEqual(rc, 1)
        self.assertIn("requests   2.31.0", out.getvalue())


def _fail_open(run_fn, args, patch_target):
    result = subprocess.CompletedProcess(
        args, 0, "raw stdout\n", "raw stderr\n"
    )
    out = io.StringIO()
    err = io.StringIO()
    raiser = mock.Mock(side_effect=RuntimeError("boom"))
    with mock.patch("actx_lib.runner.execute", return_value=result), mock.patch(
        patch_target, side_effect=raiser
    ):
        with redirect_stdout(out), redirect_stderr(err):
            rc = run_fn(args, CONFIG)
    return rc, out.getvalue(), err.getvalue()


class PackageFailOpenTests(unittest.TestCase):
    def _assert_raw(self, rc, out, err):
        self.assertEqual(rc, 0)
        self.assertEqual(out, "raw stdout\n")
        self.assertEqual(err, "raw stderr\n")

    def test_pip_fails_open(self):
        rc, out, err = _fail_open(
            package_filter.run_pip,
            ["list"],
            "actx_lib.filters.package_filter.compact_pip",
        )
        self._assert_raw(rc, out, err)

    def test_uv_fails_open(self):
        rc, out, err = _fail_open(
            package_filter.run_uv,
            ["run"],
            "actx_lib.filters.package_filter.compact_uv_run",
        )
        self._assert_raw(rc, out, err)

    def test_npm_fails_open(self):
        rc, out, err = _fail_open(
            package_filter.run_npm,
            ["list"],
            "actx_lib.filters.package_filter.compact_npm_list",
        )
        self._assert_raw(rc, out, err)

    def test_pnpm_fails_open(self):
        rc, out, err = _fail_open(
            package_filter.run_pnpm,
            ["list"],
            "actx_lib.filters.package_filter.compact_pnpm_list",
        )
        self._assert_raw(rc, out, err)


if __name__ == "__main__":
    unittest.main()
