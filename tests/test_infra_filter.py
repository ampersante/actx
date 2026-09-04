import io
import json
import subprocess
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from actx_lib.filters import infra_filter
from actx_lib.redaction import _drop_secret_json

CONFIG = {
    "tee": {"enabled": False, "mode": "failures", "dir": "~/.local/share/actx/tee"},
    "truncate": {"max_lines": 500, "max_line_chars": 300},
}

DOCKER_PS = """\
CONTAINER ID   IMAGE     COMMAND   CREATED   STATUS   PORTS   NAMES
abc123def456   nginx:1   "nginx"   2 hours   Up       ...     web
def456abc123   redis:7   "redis"   3 hours   Up       ...     cache
"""

DOCKER_LOGS = """\
request from 1.2.3.4
request from 1.2.3.4
request from 1.2.3.4
error happened
request from 1.2.3.4
"""

KUBECTL_GET = """\
NAME      READY   STATUS   RESTARTS   AGE
web-abc   1/1     Running  0          2h
web-def   1/1     Running  0          2h
"""

GH_PR_LIST = """\
ID   TITLE         BRANCH   STATE   CREATED AT
123  Fix bug       fix/bug  OPEN    2026-08-14
124  Add feature   feat/x   MERGED  2026-08-13
"""

AWS_JSON = """\
{
  "Account": "123456789012",
  "Arn": "arn:aws:iam::123456789012:user/eli",
  "AccessKeyId": "AKIAEXAMPLE",
  "SecretAccessKey": "shhh"
}
"""

AWS_TEXT = """\
line with password=secret
normal line
"""


class InfraParserTests(unittest.TestCase):
    def test_docker_ps_keeps_rows(self):
        out = infra_filter._dedup_compact(DOCKER_PS)
        self.assertIn("abc123def456", out)
        self.assertIn("def456abc123", out)

    def test_docker_logs_deduplicates_consecutive_lines(self):
        out = infra_filter._dedup_compact(DOCKER_LOGS)
        self.assertIn("request from 1.2.3.4 (x3)", out)
        self.assertIn("error happened", out)

    def test_kubectl_get_keeps_rows(self):
        out = infra_filter._dedup_compact(KUBECTL_GET)
        self.assertIn("web-abc", out)
        self.assertIn("web-def", out)

    def test_gh_pr_list_keeps_rows(self):
        out = infra_filter._dedup_compact(GH_PR_LIST)
        self.assertIn("Fix bug", out)
        self.assertIn("Add feature", out)

    def test_aws_json_drops_secret_keys(self):
        out = infra_filter.compact_aws(AWS_JSON)
        self.assertIn("Account", out)
        self.assertIn("Arn", out)
        self.assertNotIn("AccessKeyId", out)
        self.assertNotIn("SecretAccessKey", out)

    def test_aws_text_drops_secret_lines(self):
        out = infra_filter.compact_aws(AWS_TEXT)
        self.assertIn("normal line", out)
        self.assertNotIn("password", out)

    def test_aws_json_matches_legacy_dump_byte_for_byte(self):
        # compact_aws delegates to json_compactor; valid JSON must stay
        # byte-identical to the pre-TK-38 dump: indent=2, sort_keys=True,
        # no list trimming.
        text = json.dumps(
            {"zeta": [5, 1, 3], "arn": "a", "SecretAccessKey": "shhh",
             "nested": {"b": 2, "a": 1}, "Rows": [{"y": 2, "x": 1}]}
        )
        self.assertEqual(
            infra_filter.compact_aws(text),
            json.dumps(_drop_secret_json(json.loads(text)), indent=2, sort_keys=True),
        )


class InfraExitCodeTests(unittest.TestCase):
    def test_docker_preserves_exit_code(self):
        result = subprocess.CompletedProcess(["docker", "ps"], 1, DOCKER_PS, "")
        out = io.StringIO()
        err = io.StringIO()
        with mock.patch("actx_lib.runner.execute", return_value=result):
            with redirect_stdout(out), redirect_stderr(err):
                rc = infra_filter.run_docker(["ps"], CONFIG)
        self.assertEqual(rc, 1)
        self.assertIn("abc123def456", out.getvalue())


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


class InfraFailOpenTests(unittest.TestCase):
    def _assert_raw(self, rc, out, err):
        self.assertEqual(rc, 0)
        self.assertEqual(out, "raw stdout\n")
        self.assertEqual(err, "raw stderr\n")

    def test_docker_fails_open(self):
        rc, out, err = _fail_open(
            infra_filter.run_docker,
            ["ps"],
            "actx_lib.filters.infra_filter._dedup_compact",
        )
        self._assert_raw(rc, out, err)

    def test_kubectl_fails_open(self):
        rc, out, err = _fail_open(
            infra_filter.run_kubectl,
            ["get"],
            "actx_lib.filters.infra_filter._dedup_compact",
        )
        self._assert_raw(rc, out, err)

    def test_gh_fails_open(self):
        rc, out, err = _fail_open(
            infra_filter.run_gh,
            ["pr"],
            "actx_lib.filters.infra_filter._dedup_compact",
        )
        self._assert_raw(rc, out, err)

    def test_aws_fails_open(self):
        rc, out, err = _fail_open(
            infra_filter.run_aws,
            ["sts"],
            "actx_lib.filters.infra_filter.compact_aws",
        )
        self._assert_raw(rc, out, err)


if __name__ == "__main__":
    unittest.main()
