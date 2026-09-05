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

DOCKER_INSPECT_JSON = """\
[
  {"Id": "abc123def456", "Image": "nginx:1",
   "State": {"Status": "running", "Running": true}},
  {"Id": "def456abc123", "Image": "redis:7",
   "State": {"Status": "running", "Running": true}}
]
"""

# docker inspect on a missing container prints a plain error (no JSON).
DOCKER_INSPECT_INVALID = """\
Error response from daemon: No such container: nope
Error response from daemon: No such container: nope
"""

DOCKER_SYSTEM_DF = """\
TYPE            TOTAL     ACTIVE    SIZE      RECLAIMABLE
Images          3         2         1.2GB     900MB (75%)
Containers      2         2         300MB     0B (0%)
Local Volumes   5         2         500MB     200MB (40%)
Build Cache     10        0         800MB     800MB
"""

DOCKER_COMPOSE_LOGS = """\
web-1  | GET /health 200
web-1  | GET /health 200
web-1  | GET /health 200
web-1  | GET /api 200
db-1   | ready to accept connections
"""

DOCKER_STATS = """\
CONTAINER ID   NAME      CPU %   MEM USAGE / LIMIT
abc123def456   web       0.15%   120MiB / 4GiB
def456abc123   cache     0.02%   40MiB / 4GiB
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

    def test_docker_inspect_valid_json_compacts(self):
        # TK-41: inspect goes through the compact_aws pattern — valid JSON
        # must survive as parseable JSON with values intact.
        out = infra_filter.compact_aws(DOCKER_INSPECT_JSON)
        parsed = json.loads(out)
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0]["Id"], "abc123def456")
        self.assertEqual(parsed[0]["State"]["Status"], "running")
        self.assertEqual(parsed[1]["Image"], "redis:7")

    def test_docker_inspect_invalid_json_text_fallback(self):
        # `docker inspect nope` prints a plain daemon error: no JSON to
        # parse, so the compact_aws pattern falls back to _dedup_compact.
        out = infra_filter.compact_aws(DOCKER_INSPECT_INVALID)
        self.assertIn("No such container: nope", out)
        self.assertIn("(x2)", out)

    def test_docker_system_df_keeps_rows(self):
        out = infra_filter._dedup_compact(DOCKER_SYSTEM_DF)
        self.assertIn("Images", out)
        self.assertIn("Containers", out)
        self.assertIn("Local Volumes", out)
        self.assertIn("Build Cache", out)

    def test_docker_compose_logs_deduplicates_consecutive_lines(self):
        out = infra_filter._dedup_compact(DOCKER_COMPOSE_LOGS)
        self.assertIn("GET /health 200 (x3)", out)
        self.assertIn("GET /api 200", out)
        self.assertIn("ready to accept connections", out)

    def test_docker_stats_keeps_rows(self):
        out = infra_filter._dedup_compact(DOCKER_STATS)
        self.assertIn("abc123def456", out)
        self.assertIn("def456abc123", out)
        self.assertIn("MEM USAGE / LIMIT", out)


class DockerEffectiveVerbTests(unittest.TestCase):
    """TK-41 / H-F4: run_docker dispatches on the effective verb.

    Global docker value flags (--context/-H/--host, = forms) and compose
    level value flags between `compose` and its subcommand are skipped
    before the dispatch decision; bare stats and mutating verbs stay on
    the passthrough path.
    """

    def _run(self, args, stdout):
        result = subprocess.CompletedProcess(["docker"] + args, 0, stdout, "")
        out = io.StringIO()
        err = io.StringIO()
        with mock.patch("actx_lib.runner.execute", return_value=result):
            with redirect_stdout(out), redirect_stderr(err):
                rc = infra_filter.run_docker(args, CONFIG)
        return rc, out.getvalue()

    def _assert_passthrough(self, args):
        with mock.patch(
            "actx_lib.runner.run_passthrough", return_value=7
        ) as passthrough:
            rc = infra_filter.run_docker(args, CONFIG)
        self.assertEqual(rc, 7)
        passthrough.assert_called_once_with(["docker"] + args)

    def test_global_value_flag_skipped_before_verb(self):
        for args in (
            ["--context", "prod", "ps"],
            ["-H", "tcp://docker.internal:2375", "ps"],
            ["--host", "unix:///var/run/docker.sock", "images"],
            ["--context=prod", "ps"],
        ):
            with self.subTest(args=args):
                rc, out = self._run(args, DOCKER_PS)
                self.assertEqual(rc, 0)
                self.assertIn("abc123def456", out)

    def test_compose_value_flag_skipped_before_verb(self):
        # `docker compose -f x.yml ps` was a passthrough before TK-41;
        # the compose subcommand now dispatches through the flags. The
        # plain flag-less form keeps its pre-TK-41 compaction.
        for args in (["compose", "ps"], ["compose", "-f", "x.yml", "ps"]):
            with self.subTest(args=args):
                rc, out = self._run(args, DOCKER_PS)
                self.assertEqual(rc, 0)
                self.assertIn("abc123def456", out)

    def test_compose_flag_value_never_read_as_verb(self):
        # A compose file literally named "logs" is a -f VALUE: the
        # subcommand after it decides the path, not the value token.
        rc, out = self._run(["compose", "-f", "logs", "ps"], DOCKER_PS)
        self.assertEqual(rc, 0)
        self.assertIn("abc123def456", out)

    def test_inspect_dispatches_to_json_parser(self):
        rc, out = self._run(["--context", "prod", "inspect", "web"],
                            DOCKER_INSPECT_JSON)
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out)[0]["Id"], "abc123def456")

    def test_system_df_compacts(self):
        rc, out = self._run(["system", "df"], DOCKER_SYSTEM_DF)
        self.assertEqual(rc, 0)
        self.assertIn("Build Cache", out)

    def test_stats_no_stream_compacts(self):
        rc, out = self._run(["stats", "--no-stream"], DOCKER_STATS)
        self.assertEqual(rc, 0)
        self.assertIn("abc123def456", out)

    def test_compose_logs_compacts(self):
        rc, out = self._run(["compose", "logs"], DOCKER_COMPOSE_LOGS)
        self.assertEqual(rc, 0)
        self.assertIn("GET /health 200 (x3)", out)

    def test_bare_stats_and_mutating_verbs_stay_passthrough(self):
        for args in (
            ["stats"],                          # streams; never-wrap in hook
            ["system", "prune"],
            ["rm", "x"],
            ["rmi", "x"],
            ["volume", "rm", "x"],
            ["volume", "prune"],
            ["compose", "up", "-d"],
            ["compose", "build"],
            ["--context"],                      # dangling value flag
            [],                                 # bare head handled upstream
        ):
            with self.subTest(args=args):
                self._assert_passthrough(args)


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

    def test_docker_new_paths_preserve_exit_code(self):
        # TK-41 paths: inspect (JSON parser + text fallback), system df,
        # stats --no-stream, compose logs — exit code passthrough each.
        for args, stdout in (
            (["inspect", "web"], DOCKER_INSPECT_JSON),
            (["inspect", "nope"], DOCKER_INSPECT_INVALID),
            (["system", "df"], DOCKER_SYSTEM_DF),
            (["stats", "--no-stream"], DOCKER_STATS),
            (["compose", "logs"], DOCKER_COMPOSE_LOGS),
        ):
            with self.subTest(args=args):
                result = subprocess.CompletedProcess(
                    ["docker"] + args, 3, stdout, ""
                )
                out = io.StringIO()
                err = io.StringIO()
                with mock.patch(
                    "actx_lib.runner.execute", return_value=result
                ):
                    with redirect_stdout(out), redirect_stderr(err):
                        rc = infra_filter.run_docker(args, CONFIG)
                self.assertEqual(rc, 3)


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

    def test_docker_inspect_fails_open(self):
        # TK-41: the JSON parser path fails open to raw output too.
        rc, out, err = _fail_open(
            infra_filter.run_docker,
            ["inspect", "c"],
            "actx_lib.filters.infra_filter.compact_aws",
        )
        self._assert_raw(rc, out, err)

    def test_docker_system_df_fails_open(self):
        rc, out, err = _fail_open(
            infra_filter.run_docker,
            ["system", "df"],
            "actx_lib.filters.infra_filter._dedup_compact",
        )
        self._assert_raw(rc, out, err)

    def test_docker_stats_no_stream_fails_open(self):
        rc, out, err = _fail_open(
            infra_filter.run_docker,
            ["stats", "--no-stream"],
            "actx_lib.filters.infra_filter._dedup_compact",
        )
        self._assert_raw(rc, out, err)

    def test_docker_compose_logs_fails_open(self):
        rc, out, err = _fail_open(
            infra_filter.run_docker,
            ["compose", "logs"],
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
