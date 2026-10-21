"""TK-58 pack 1 (runner/cli/config/filters): reliability acceptance.

CHK-01..CHK-09, CHK-11, CHK-12 of scratch/tk58/plan.md. Fake tools live on
a scratch PATH and HOME is a temporary directory; the owner's HOME is never
touched.
"""

import io
import json
import os
import shlex
import signal
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from actx_lib import cli, config as config_mod, runner
from actx_lib.filters import (
    REGISTRY,
    data_filter,
    infra_filter,
    linter_filter,
    mobile_filter,
    package_filter,
    system_filter,
    test_runner_filter,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACTX = os.path.join(ROOT, "actx")
FFFD = "�".encode("utf-8")
BASE_PATH = "/usr/bin:/bin"


class _Scratch(unittest.TestCase):
    """Temporary HOME + bin dir; fake tools are /bin/sh scripts."""

    def setUp(self):
        self._home = tempfile.TemporaryDirectory()
        self._bin = tempfile.TemporaryDirectory()
        self._work = tempfile.TemporaryDirectory()
        self.home = self._home.name
        self.bin = self._bin.name
        self.work = self._work.name
        self.addCleanup(self._home.cleanup)
        self.addCleanup(self._bin.cleanup)
        self.addCleanup(self._work.cleanup)
        # Once-per-process warning sets: start and leave them empty so
        # in-process tests elsewhere see a fresh process.
        for name, module in (("_WARNED", config_mod), ("_WARNED_RESERVED", cli)):
            if hasattr(module, name):
                getattr(module, name).clear()
                self.addCleanup(getattr(module, name).clear)

    @property
    def tee_dir(self):
        return os.path.join(self.home, ".local", "share", "actx", "tee")

    def tool(self, name, body, executable=True):
        path = os.path.join(self.bin, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("#!/bin/sh\n" + body)
        os.chmod(path, 0o755 if executable else 0o644)
        return path

    def write_config(self, data):
        path = os.path.join(self.home, ".config", "actx", "config.json")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(data, handle)

    def env(self, path=None):
        env = os.environ.copy()
        env["HOME"] = self.home
        env["PATH"] = self.bin + os.pathsep + (path or BASE_PATH)
        env.pop("ACTX_BYPASS", None)
        env.pop("ACTX_TRACKING", None)
        return env

    def actx(self, *args, path=None, timeout=60):
        return subprocess.run(
            [sys.executable, ACTX] + list(args),
            capture_output=True, env=self.env(path), cwd=self.work,
            timeout=timeout,
        )

    def popen(self, *args):
        proc = subprocess.Popen(
            [sys.executable, ACTX] + list(args),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=self.env(), cwd=self.work,
        )
        self.addCleanup(self._reap, proc)
        return proc

    @staticmethod
    def _reap(proc):
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        for stream in (proc.stdout, proc.stderr):
            if stream:
                stream.close()

    def wait_for(self, path, seconds=15):
        deadline = time.time() + seconds
        while time.time() < deadline:
            if os.path.exists(path):
                return
            time.sleep(0.05)
        self.fail("fake tool never became ready: %s" % path)

    def tracking_rows(self):
        db = os.path.join(self.home, ".local", "share", "actx", "history.db")
        if not os.path.exists(db):
            return 0
        conn = sqlite3.connect(db)
        try:
            return conn.execute("SELECT COUNT(*) FROM calls").fetchone()[0]
        finally:
            conn.close()

    def tee_files(self, tee_dir=None):
        tee_dir = tee_dir or self.tee_dir
        if not os.path.isdir(tee_dir):
            return []
        return sorted(os.path.join(tee_dir, n) for n in os.listdir(tee_dir))

    def counter(self):
        path = os.path.join(self.work, "counter")
        if not os.path.exists(path):
            return 0
        with open(path, encoding="utf-8") as handle:
            return len(handle.read().split())

    def counting(self, rest):
        """Body prefix: count every start of the fake tool."""
        return "echo x >> %s\n%s" % (
            shlex.quote(os.path.join(self.work, "counter")), rest,
        )

    def main_inproc(self, argv, *patches):
        """cli.main in-process with bytes-capturing stdout/stderr."""
        out_b, err_b = io.BytesIO(), io.BytesIO()
        out = io.TextIOWrapper(out_b, encoding="utf-8", newline="")
        err = io.TextIOWrapper(err_b, encoding="utf-8", newline="")
        env = {"HOME": self.home, "PATH": self.bin + os.pathsep + BASE_PATH}
        with mock.patch.dict(os.environ, env), mock.patch(
            "sys.stdout", out
        ), mock.patch("sys.stderr", err):
            for patch in patches:
                patch.start()
            try:
                rc = cli.main(["actx"] + list(argv))
            finally:
                for patch in reversed(patches):
                    patch.stop()
                out.flush()
                err.flush()
        result = (rc, out_b.getvalue(), err_b.getvalue())
        out.detach()
        err.detach()
        return result


def _capture(fn, *args, **kwargs):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = fn(*args, **kwargs)
    return rc, out.getvalue(), err.getvalue()


def _config(tee=None):
    return {
        "tee": tee or {"enabled": False},
        "truncate": {"max_lines": 500, "max_line_chars": 300},
    }


# --------------------------------------------------------------- CHK-01


class NonUtf8OutputTests(_Scratch):
    BODY = "printf 'a\\377b\\n'; printf 'e\\377r\\n' >&2; exit 3\n"

    def assert_clean(self, p):
        self.assertNotIn(b"Traceback", p.stderr)
        self.assertNotIn(b"UnicodeDecodeError", p.stderr)
        self.assertEqual(p.returncode, 3, p.stderr)

    def assert_tee(self):
        files = self.tee_files()
        self.assertEqual(len(files), 1, files)
        with open(files[0], encoding="utf-8") as handle:
            record = json.load(handle)
        self.assertEqual(record["exit_code"], 3)
        self.assertIn("a�b", record["stdout"])
        self.assertIn("e�r", record["stderr"])

    def test_run(self):
        self.tool("t", self.BODY)
        p = self.actx("run", "t")
        self.assert_clean(p)
        self.assertIn(b"a" + FFFD + b"b", p.stdout)
        self.assertIn(b"e" + FFFD + b"r", p.stderr)
        self.assertEqual(self.tracking_rows(), 1)
        self.assert_tee()

    def test_filter(self):
        self.tool("ruff", self.BODY)
        p = self.actx("ruff", "check", ".")
        self.assert_clean(p)
        self.assertIn(b"a" + FFFD + b"b", p.stdout)
        self.assertIn(b"e" + FFFD + b"r", p.stderr)
        self.assertEqual(self.tracking_rows(), 1)
        self.assert_tee()

    def test_run_digest(self):
        self.tool("t", self.BODY)
        p = self.actx("run", "--digest", "t")
        self.assert_clean(p)
        self.assertIn(b"a" + FFFD + b"b", p.stdout)
        self.assertEqual(self.tracking_rows(), 1)

    def test_run_errors(self):
        self.tool("t", self.BODY)
        p = self.actx("run", "--errors", "t")
        self.assert_clean(p)
        self.assertEqual(p.stdout, b"")
        self.assertIn(b"e" + FFFD + b"r", p.stderr)
        self.assertEqual(self.tracking_rows(), 1)


# --------------------------------------------------------------- CHK-02

_SITES = (
    ("Package", package_filter.run_pip, ["install", "x"]),
    ("Data", data_filter.run_dbt, ["run"]),
    ("Pytest", test_runner_filter.run_pytest, []),
    ("Jest", test_runner_filter.run_jest, []),
    ("Vitest", test_runner_filter.run_vitest, []),
    ("Cargo", test_runner_filter.run_cargo_test, ["test"]),
    ("Go", test_runner_filter.run_go_test, ["test"]),
    ("InfraDocker", infra_filter.run_docker, ["ps"]),
    ("InfraKubectlTop", infra_filter.run_kubectl, ["top", "pods"]),
    ("Linter", linter_filter.run_ruff, ["check", "."]),
    ("MobileTest", mobile_filter.run_flutter, ["test"]),
    ("MobileLint", mobile_filter.run_swiftlint, ["lint"]),
)


class _StderrOnFailure:
    """compacted_result caller, exit != 0: masked stderr shown exactly once."""

    entry = None
    args = None

    def test_stderr_marker_once_exit_preserved(self):
        result = subprocess.CompletedProcess(
            ["x"], 2, "some output line\n", "MARKER-ERR token=abc123\n"
        )
        with mock.patch("actx_lib.runner.execute", return_value=result):
            rc, out, err = _capture(type(self).entry, list(self.args), _config())
        self.assertEqual(rc, 2)
        self.assertEqual(err.count("MARKER-ERR"), 1, err)
        self.assertNotIn("abc123", err)


for _name, _entry, _args in _SITES:
    _cls = type(
        "StderrOnFailure%sTests" % _name,
        (_StderrOnFailure, unittest.TestCase),
        {"entry": staticmethod(_entry), "args": _args},
    )
    globals()[_cls.__name__] = _cls
del _name, _entry, _args, _cls


# --------------------------------------------------------------- CHK-03


class StderrOnSuccessTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tee_dir = os.path.join(self._tmp.name, "tee")

    def run_pip(self, stderr, tee=None, rc=0):
        result = subprocess.CompletedProcess(
            ["pip", "install", "x"], rc, "Successfully installed foo-1.0\n", stderr
        )
        cfg = _config(tee)
        with mock.patch("actx_lib.runner.execute", return_value=result):
            return _capture(package_filter.run_pip, ["install", "x"], cfg)

    def files(self):
        if not os.path.isdir(self.tee_dir):
            return []
        return [os.path.join(self.tee_dir, n) for n in os.listdir(self.tee_dir)]

    @staticmethod
    def long_stderr(extra=()):
        lines = ["progress %d" % i for i in range(200 - 2 - len(extra))]
        lines[50:50] = ["warning: x", "https://github.com/o/r/pull/1"]
        lines[100:100] = list(extra)
        return "\n".join(lines) + "\n"

    def hint_lines(self, err):
        return [l for l in err.splitlines() if "stderr lines hidden" in l]

    def test_short_stderr_whole(self):
        stderr = "".join("note %d\n" % i for i in range(5))
        rc, out, err = self.run_pip(stderr)
        self.assertEqual(rc, 0)
        self.assertIn("Successfully installed", out)
        self.assertEqual(err, stderr)

    def test_long_stderr_significant_lines_and_one_hint(self):
        stderr = self.long_stderr()
        tee = {"enabled": True, "mode": "failures", "dir": self.tee_dir}
        rc, out, err = self.run_pip(stderr, tee)
        self.assertEqual(rc, 0)
        self.assertIn("warning: x\n", err)
        self.assertIn("https://github.com/o/r/pull/1\n", err)
        self.assertNotIn("progress 7\n", err)
        hints = self.hint_lines(err)
        self.assertEqual(len(hints), 1, err)
        files = self.files()
        self.assertEqual(len(files), 1, files)
        self.assertEqual(
            hints[0], "[actx] 198 stderr lines hidden; full output: %s" % files[0]
        )
        self.assertNotIn("[full output:", err)
        with open(files[0], encoding="utf-8") as handle:
            record = json.load(handle)
        self.assertEqual(record["stderr"], stderr)

    def test_tee_write_failure_prints_whole_stderr(self):
        blocker = os.path.join(self._tmp.name, "file")
        with open(blocker, "w") as handle:
            handle.write("x")
        stderr = self.long_stderr()
        tee = {"enabled": True, "dir": os.path.join(blocker, "tee")}
        rc, out, err = self.run_pip(stderr, tee)
        self.assertEqual(rc, 0)
        self.assertIn(stderr, err)
        self.assertEqual(self.hint_lines(err), [])

    def test_stderr_over_stream_limit_whole(self):
        chunk = "x" * (450 * 1024)
        stderr = "".join("%s %d\n" % (chunk, i) for i in range(25))
        tee = {"enabled": True, "dir": self.tee_dir}
        rc, out, err = self.run_pip(stderr, tee)
        self.assertEqual(rc, 0)
        self.assertEqual(err.count(chunk), 25)
        self.assertEqual(self.hint_lines(err), [])
        self.assertEqual(self.files(), [])

    def test_tee_mode_always_one_file(self):
        tee = {"enabled": True, "mode": "always", "dir": self.tee_dir}
        rc, out, err = self.run_pip(self.long_stderr(), tee)
        self.assertEqual(rc, 0)
        self.assertEqual(len(self.files()), 1, self.files())
        self.assertEqual(len(self.hint_lines(err)), 1)
        self.assertNotIn("[full output:", err)

    def test_failures_mode_green_is_silent(self):
        result = subprocess.CompletedProcess(
            ["pytest"], 0, "5 passed in 0.1s\n", "warning: deprecated thing\n" * 30
        )
        with mock.patch("actx_lib.runner.execute", return_value=result):
            rc, out, err = _capture(
                test_runner_filter.run_failures, ["pytest"], _config()
            )
        self.assertEqual((rc, out, err), (0, "", ""))

    def test_secrets_masked_on_failure_and_long_success(self):
        secret = "token=abc123\nAuthorization: Bearer xyz\n"
        rc, out, err = self.run_pip(secret, rc=1)
        self.assertEqual(rc, 1)
        self.assertIn("token=", err)
        self.assertNotIn("abc123", err)
        self.assertNotIn("xyz", err)
        stderr = self.long_stderr(
            ["error: token=abc123", "fatal: Authorization: Bearer xyz"]
        )
        tee = {"enabled": True, "dir": self.tee_dir}
        rc, out, err = self.run_pip(stderr, tee)
        self.assertEqual(rc, 0)
        self.assertIn("error: token=", err)
        self.assertNotIn("abc123", err)
        self.assertNotIn("xyz", err)
        self.assertEqual(len(self.hint_lines(err)), 1)


# --------------------------------------------------------------- CHK-04


class AnsiTests(_Scratch):
    def test_coloured_pytest_failed_name(self):
        stdout = (
            "\x1b[31m=========================== short test summary info "
            "============================\x1b[0m\n"
            "\x1b[31mFAILED\x1b[0m t.py::x - msg\n"
            "\x1b[31m1 failed\x1b[0m in 0.1s\n"
        )
        result = subprocess.CompletedProcess(["pytest"], 1, stdout, "")
        with mock.patch("actx_lib.runner.execute", return_value=result):
            rc, out, err = _capture(test_runner_filter.run_pytest, [], _config())
        self.assertEqual(rc, 1)
        self.assertIn("t.py::x - msg", out)
        self.assertNotIn("\x1b", out)

    def test_coloured_ruff_and_swiftlint(self):
        cases = (
            (linter_filter.run_ruff, ["check", "."],
             "\x1b[1ma.py\x1b[0m:1:1: \x1b[31mE1\x1b[0m bad\n", "a.py:1:1: E1 bad"),
            (mobile_filter.run_swiftlint, ["lint"],
             "\x1b[33mx.swift:1:2: warning: bad (rule)\x1b[0m\n",
             "x.swift:1:2: warning: bad (rule)"),
        )
        for entry, args, stdout, finding in cases:
            with self.subTest(entry=entry.__name__):
                result = subprocess.CompletedProcess(["x"], 1, stdout, "")
                with mock.patch("actx_lib.runner.execute", return_value=result):
                    rc, out, err = _capture(entry, args, _config())
                self.assertEqual(rc, 1)
                self.assertIn(finding, out)
                self.assertNotIn("\x1b", out)

    def test_git_log_color_always(self):
        path = os.environ.get("PATH", BASE_PATH)
        env = self.env(path)
        git = ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid"]
        subprocess.run(["git", "init", "-q"], cwd=self.work, env=env, check=True)
        subprocess.run(
            git + ["commit", "-q", "--allow-empty", "-m", "first"],
            cwd=self.work, env=env, check=True,
        )
        p = self.actx("git", "log", "--color=always", path=path)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn(b"first", p.stdout)
        self.assertNotIn(b"\x1b", p.stdout)


# --------------------------------------------------------------- CHK-05


class ExitCodeTests(_Scratch):
    def test_signal_death_is_128_plus_n(self):
        self.tool("k", "kill -9 $$\n")
        self.tool("ruff", "kill -9 $$\n")
        for args in (("run", "k"), ("--raw", "run", "k"), ("ruff", "check", ".")):
            with self.subTest(args=args):
                p = self.actx(*args)
                self.assertEqual(p.returncode, 137, p.stderr)
                self.assertNotIn(b"Traceback", p.stderr)

    def test_missing_tool_127_everywhere(self):
        for args in (
            ("run", "nosuchtool"),
            ("run", "--errors", "nosuchtool"),
            ("run", "--digest", "nosuchtool"),
            ("ruff", "check", "."),
        ):
            with self.subTest(args=args):
                p = self.actx(*args)
                self.assertEqual(p.returncode, 127, p.stderr)
                self.assertIn(b"command not found", p.stderr)
                self.assertNotIn(b"Traceback", p.stderr)

    def test_non_executable_126_everywhere(self):
        self.tool("ne", "echo hi\n", executable=False)
        self.tool("ruff", "echo hi\n", executable=False)
        for args in (
            ("run", "ne"),
            ("run", "--errors", "ne"),
            ("run", "--digest", "ne"),
            ("ruff", "check", "."),
        ):
            with self.subTest(args=args):
                p = self.actx(*args)
                self.assertEqual(p.returncode, 126, p.stderr)
                self.assertNotIn(b"Traceback", p.stderr)

    def _signal_case(self, body, sig):
        ready = os.path.join(self.work, "ready")
        self.tool("t", body % {"ready": shlex.quote(ready)})
        proc = self.popen("run", "t")
        self.wait_for(ready)
        proc.send_signal(sig)
        out, err = proc.communicate(timeout=20)
        return proc.returncode, err

    def test_child_handling_sigint_keeps_its_code(self):
        rc, err = self._signal_case(
            "trap 'exit 42' INT\n: > %(ready)s\n"
            "while :; do sleep 0.1; done\n",
            signal.SIGINT,
        )
        self.assertEqual(rc, 42, err)
        self.assertNotIn(b"Traceback", err)

    def test_default_sigint_child_is_130(self):
        rc, err = self._signal_case(": > %(ready)s\nsleep 30\n", signal.SIGINT)
        self.assertEqual(rc, 130, err)
        self.assertNotIn(b"Traceback", err)

    def test_default_sigterm_child_is_143(self):
        rc, err = self._signal_case(": > %(ready)s\nsleep 30\n", signal.SIGTERM)
        self.assertEqual(rc, 143, err)
        self.assertNotIn(b"Traceback", err)


class SpawnSeamTests(unittest.TestCase):
    def test_spawn_popen_arguments(self):
        proc = mock.MagicMock()
        proc.pid = 999999
        proc.returncode = 0
        proc.communicate.return_value = ("o", "e")
        with mock.patch("actx_lib.runner.subprocess.Popen", return_value=proc) as popen:
            result = runner._spawn(["x", "y"], timeout=5, text=True)
        self.assertEqual(result.stdout, "o")
        self.assertEqual(result.returncode, 0)
        args, kwargs = popen.call_args
        self.assertEqual(args[0], ["x", "y"])
        self.assertIs(kwargs["stdin"], subprocess.DEVNULL)
        self.assertIs(kwargs["stdout"], subprocess.PIPE)
        self.assertIs(kwargs["stderr"], subprocess.PIPE)
        self.assertTrue(kwargs["start_new_session"])
        self.assertEqual(kwargs["encoding"], "utf-8")
        self.assertEqual(kwargs["errors"], "replace")
        proc.communicate.assert_called_once_with(timeout=5)

    def test_spawn_bytes_mode_has_no_encoding(self):
        proc = mock.MagicMock()
        proc.pid = 999999
        proc.returncode = -9
        proc.communicate.return_value = (b"o", b"")
        with mock.patch("actx_lib.runner.subprocess.Popen", return_value=proc) as popen:
            result = runner._spawn(["x"], timeout=5, text=False)
        self.assertNotIn("encoding", popen.call_args.kwargs)
        self.assertEqual(result.returncode, 137)


# --------------------------------------------------------------- CHK-06


class ConfigTypeTests(_Scratch):
    WARN = "[actx] config: '%s' has wrong type, using default"

    def warnings(self, err):
        return [l for l in err.decode().splitlines() if "[actx] config:" in l]

    def test_wrong_types_fall_back_with_one_warning(self):
        self.tool("ruff", "echo one\necho two\necho three\nexit 5\n")
        cases = (
            ({"tee": "oops"}, "tee"),
            ({"timeouts": "x"}, "timeouts"),
            ({"truncate": {"max_lines": "x"}}, "truncate.max_lines"),
            ({"truncate": {"max_lines": 1.5}}, "truncate.max_lines"),
            ({"tracking": {"enabled": 1}}, "tracking.enabled"),
        )
        for data, key in cases:
            with self.subTest(config=data):
                self.write_config(data)
                p = self.actx("ruff", "check", ".")
                self.assertEqual(p.returncode, 5, p.stderr)
                self.assertNotIn(b"Traceback", p.stderr)
                self.assertEqual(self.warnings(p.stderr), [self.WARN % key])

    def test_float_max_lines_on_generic_run(self):
        self.tool("t", "echo one\necho two\necho three\nexit 5\n")
        self.write_config({"truncate": {"max_lines": 1.5}})
        p = self.actx("run", "t")
        self.assertEqual(p.returncode, 5, p.stderr)
        self.assertNotIn(b"TypeError", p.stderr)
        self.assertEqual(p.stdout, b"one\ntwo\nthree\n")
        self.assertEqual(
            self.warnings(p.stderr), [self.WARN % "truncate.max_lines"]
        )

    def test_float_timeout_accepted(self):
        self.tool("t", "sleep 5\n")
        self.write_config({"timeouts": {"default_s": 1.5}})
        start = time.time()
        p = self.actx("run", "t")
        self.assertEqual(p.returncode, runner.TIMEOUT_EXIT_CODE, p.stderr)
        self.assertLess(time.time() - start, 4.5)
        self.assertEqual(self.warnings(p.stderr), [])

    def test_merge_unit_rules(self):
        merged = config_mod._merge(
            config_mod.DEFAULT_CONFIG,
            {"tee": {"enabled": "yes", "min_bytes": True, "extra": 1},
             "timeouts": {"generous_s": 2.5}, "custom_heads": "x",
             "ultra_compact": True},
        )
        self.assertIs(merged["tee"]["enabled"], True)
        self.assertEqual(merged["tee"]["min_bytes"], 0)
        self.assertEqual(merged["tee"]["extra"], 1)
        self.assertEqual(merged["timeouts"]["generous_s"], 2.5)
        self.assertEqual(merged["timeouts"]["default_s"], 600)
        self.assertEqual(merged["custom_heads"], [])
        self.assertIs(merged["ultra_compact"], True)


# --------------------------------------------------------------- CHK-07


class TeeModeTests(_Scratch):
    def test_new_tee_dir_and_file_modes(self):
        p = self.actx("run", "false")
        self.assertEqual(p.returncode, 1)
        self.assertEqual(stat.S_IMODE(os.stat(self.tee_dir).st_mode), 0o700)
        files = self.tee_files()
        self.assertEqual(len(files), 1)
        self.assertEqual(stat.S_IMODE(os.stat(files[0]).st_mode), 0o600)

    def test_existing_open_dir_is_tightened(self):
        os.makedirs(self.tee_dir)
        os.chmod(self.tee_dir, 0o755)
        old = os.path.join(self.tee_dir, "1_old.log")
        with open(old, "w") as handle:
            handle.write("{}")
        os.chmod(old, 0o644)
        p = self.actx("run", "false")
        self.assertEqual(p.returncode, 1)
        self.assertEqual(stat.S_IMODE(os.stat(self.tee_dir).st_mode), 0o700)
        new = [f for f in self.tee_files() if f != old]
        self.assertEqual(len(new), 1)
        self.assertEqual(stat.S_IMODE(os.stat(new[0]).st_mode), 0o600)


# --------------------------------------------------------------- CHK-08


class PytestPaddedSectionTests(unittest.TestCase):
    TEXT = (
        "============================= test session starts ==============================\n"
        "collected 10 items\n\n"
        "test_foo.py ..F [100%]\n\n"
        "=================================== FAILURES ===================================\n"
        "_____________________________ test_half ________________________________________\n\n"
        "    def test_half():\n"
        ">       assert 1 == 2\n"
        "E       assert 1 == 2\n\n"
        "test_foo.py:4: AssertionError\n"
        "=========================== short test summary info ============================\n"
        "FAILED test_foo.py::test_half - assert 1 == 2\n"
        "======================== 1 failed, 9 passed in 0.45s ==========================\n"
    )

    def test_failures_body_once_summary_once(self):
        out = test_runner_filter.compact(self.TEXT, "pytest")
        self.assertEqual(out.count("E       assert 1 == 2"), 1, out)
        self.assertEqual(out.count("test_foo.py::test_half - assert 1 == 2"), 1, out)
        self.assertEqual(out.count("1 failed, 9 passed"), 1, out)
        self.assertNotIn("short test summary info", out)


# --------------------------------------------------------------- CHK-09


class ProcessLifecycleTests(_Scratch):
    SLEEP = "37.5713"

    def tearDown(self):
        subprocess.run(["pkill", "-f", "sleep %s" % self.SLEEP], capture_output=True)

    def test_timeout_kills_process_group(self):
        self.write_config({"timeouts": {"default_s": 2}})
        self.tool("t", "sleep %s &\nwait\n" % self.SLEEP)
        start = time.time()
        p = self.actx("run", "t", timeout=90)
        elapsed = time.time() - start
        self.assertEqual(p.returncode, runner.TIMEOUT_EXIT_CODE, p.stderr)
        self.assertLess(elapsed, 15)
        left = subprocess.run(
            ["pgrep", "-f", "sleep %s" % self.SLEEP], capture_output=True
        )
        self.assertEqual(left.stdout, b"")

    def _broken_pipe(self, *args):
        proc = self.popen(*args)
        proc.stdout.read(1024)
        proc.stdout.close()
        err = proc.stderr.read()
        proc.wait(timeout=30)
        return proc.returncode, err

    def test_broken_pipe_keeps_child_code(self):
        self.tool(
            "big",
            "head -c 1048576 /dev/zero | tr '\\0' 'x'\necho\nexit 7\n",
        )
        # Valid JSON is printed whole on the text path (never capped).
        self.tool(
            "json",
            "printf '\"'; head -c 1048576 /dev/zero | tr '\\0' 'x'\n"
            "printf '\"\\n'\nexit 7\n",
        )
        for args in (("--raw", "run", "big"), ("run", "json")):
            with self.subTest(args=args):
                rc, err = self._broken_pipe(*args)
                self.assertEqual(rc, 7, err)
                self.assertNotIn(b"BrokenPipe", err)
                self.assertNotIn(b"Exception ignored", err)
                self.assertNotIn(b"Traceback", err)

    def internal_errors(self, err):
        return [l for l in err.decode("utf-8", "replace").splitlines()
                if l.startswith("[actx] internal error")]

    def test_error_before_spawn_runs_once(self):
        self.tool("c", self.counting("printf 'out-line\\n'\nexit 4\n"))
        boom = mock.patch(
            "actx_lib.runner._timeout_seconds", side_effect=RuntimeError("boom")
        )
        rc, out, err = self.main_inproc(["run", "c"], boom)
        self.assertEqual(rc, 4, err)
        self.assertEqual(out, b"out-line\n")
        self.assertEqual(self.internal_errors(err), ["[actx] internal error: RuntimeError"])
        self.assertEqual(self.counter(), 1)

    def test_error_after_spawn_text_result_emitted_once(self):
        self.tool("c", self.counting("printf 'out-line token=abc123\\n'\nexit 4\n"))
        boom = mock.patch(
            "actx_lib.user_filter.load", side_effect=RuntimeError("boom")
        )
        rc, out, err = self.main_inproc(["run", "c"], boom)
        self.assertEqual(rc, 4, err)
        self.assertEqual(out.count(b"out-line"), 1, out)
        self.assertNotIn(b"abc123", out)
        self.assertEqual(len(self.internal_errors(err)), 1)
        self.assertEqual(self.counter(), 1)

    def _bytes_case(self, argv, head, payload_cmd, expected):
        self.tool(head, self.counting(payload_cmd + "exit 6\n"))
        real = runner._write_masked_bytes
        calls = []

        def flaky(result):
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError("boom")
            return real(result)

        boom = mock.patch("actx_lib.runner._write_masked_bytes", side_effect=flaky)
        rc, out, err = self.main_inproc(argv, boom)
        self.assertEqual(rc, 6, err[:500])
        self.assertEqual(len(out), len(expected))
        self.assertEqual(out, expected)
        self.assertEqual(len(self.internal_errors(err)), 1)
        self.assertEqual(self.counter(), 1)

    def test_error_after_spawn_bytes_result_emitted_once(self):
        small = ("printf 'a\\377b\\n'\n", b"a\xffb\n")
        size = 11 * 1024 * 1024
        large = ("head -c %d /dev/zero | tr '\\0' 'x'\n" % size, b"x" * size)
        for label, (cmd, expected) in (("small", small), ("large", large)):
            for argv, head in ((["cat", "f"], "cat"), (["--raw", "run", "p"], "p")):
                with self.subTest(payload=label, argv=argv):
                    if os.path.exists(os.path.join(self.work, "counter")):
                        os.remove(os.path.join(self.work, "counter"))
                    self._bytes_case(argv, head, cmd, expected)

    def test_error_in_tracking_after_print_output_once(self):
        self.tool("c", self.counting("printf 'out-line\\n'\nexit 4\n"))
        self.tool("ruff", self.counting("printf 'a.py:1:1: E1 bad\\n'\nexit 1\n"))
        boom = mock.patch("actx_lib.tracking.record", side_effect=RuntimeError("boom"))
        for argv, needle, code in (
            (["run", "c"], b"out-line", 4),
            (["ruff", "check", "."], b"a.py:1:1: E1 bad", 1),
        ):
            with self.subTest(argv=argv):
                if os.path.exists(os.path.join(self.work, "counter")):
                    os.remove(os.path.join(self.work, "counter"))
                rc, out, err = self.main_inproc(argv, boom)
                self.assertEqual(rc, code, err)
                self.assertEqual(out.count(needle), 1, out)
                self.assertEqual(self.counter(), 1)
                self.assertNotIn(b"Traceback", err)

    def test_init_error_never_spawns(self):
        boom = mock.patch(
            "actx_lib.installer.main", side_effect=RuntimeError("boom")
        )
        popen = mock.patch("subprocess.Popen")
        with popen as spawned:
            with self.assertRaises(RuntimeError):
                self.main_inproc(["init", "--agent", "claude"], boom)
        spawned.assert_not_called()

    def test_tty_read_fails_fast(self):
        start = time.time()
        p = self.actx("run", "sh", "-c", "exec </dev/tty; echo opened", timeout=30)
        self.assertLess(time.time() - start, 10)
        self.assertNotEqual(p.returncode, 0)
        self.assertNotIn(b"opened", p.stdout)


# --------------------------------------------------------------- CHK-11


class FindAndTeeDecisionTests(unittest.TestCase):
    def test_find_fprint0_is_passthrough(self):
        with mock.patch(
            "actx_lib.runner.run_passthrough", return_value=0
        ) as passthrough, mock.patch("actx_lib.runner.execute") as execute:
            rc = system_filter.run_find([".", "-fprint0", "f"], _config())
        self.assertEqual(rc, 0)
        passthrough.assert_called_once_with(["find", ".", "-fprint0", "f"])
        execute.assert_not_called()

    def test_no_grep_no_match_parameter(self):
        import inspect

        self.assertNotIn(
            "grep_no_match", inspect.signature(runner.tee_decision).parameters
        )
        for name in os.listdir(os.path.join(ROOT, "actx_lib")):
            if name.endswith(".py"):
                with open(os.path.join(ROOT, "actx_lib", name), encoding="utf-8") as h:
                    self.assertNotIn("grep_no_match", h.read(), name)


# --------------------------------------------------------------- CHK-12


class ReservedHeadWarningTests(_Scratch):
    def test_reserved_warning_once_e2e(self):
        self.write_config({"custom_heads": ["cat", "mytool"]})
        self.tool("mytool", "echo ok\n")
        p = self.actx("mytool", "get")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn(b"ok", p.stdout)
        self.assertEqual(p.stderr.count(b"ignoring reserved custom head: cat"), 1)

    def test_reserved_warning_once_per_process(self):
        cfg = {"custom_heads": ["cat", "mytool"]}
        err = io.StringIO()
        with redirect_stderr(err):
            self.assertTrue(cli._custom_head_requested("mytool", cfg, REGISTRY))
            self.assertTrue(cli._custom_head_requested("mytool", cfg, REGISTRY))
        self.assertEqual(err.getvalue().count("ignoring reserved custom head: cat"), 1)


if __name__ == "__main__":
    unittest.main()
