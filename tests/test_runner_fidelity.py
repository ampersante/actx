"""TK-61 C2: runner primitives and output survival (in-process, mocked
subprocess; red on 592475b, green after C2).

run_content (bytes 1:1 except masked secret values), run_lossless cap/stderr
forms and the shell exec-failure mapping, the JSON predicate, forced tee on
every cut and entry-omitting listing, stdout surviving non-zero exits, the
never-empty guard (with the --failures exception) and the tree split.
"""

import io
import json
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from actx_lib import redaction, runner
from actx_lib.filters import (
    git_filter,
    read_filter,
    smart_filter,
    system_filter,
    test_runner_filter,
    tree_filter,
)

MASK = "‹masked›"


def synthetic_text():
    """2500+ lines: repeats, tabs, trailing spaces, a 5000-char line, ANSI,
    unicode."""
    lines = ["line %04d\tcol  " % i for i in range(2500)]
    lines[10:13] = ["same"] * 3
    lines.append("x" * 5000)
    lines.append("\x1b[31mred\x1b[0m ünïcödé")
    return "\n".join(lines) + "\n"


class _Base(unittest.TestCase):
    def setUp(self):
        home = tempfile.TemporaryDirectory()
        self.addCleanup(home.cleanup)
        self.home = home.name
        env = mock.patch.dict(
            os.environ, {"HOME": self.home, "ACTX_TRACKING": "0"}
        )
        env.start()
        self.addCleanup(env.stop)
        self.tee_dir = os.path.join(self.home, "tee")
        self.config = {
            "tee": {"enabled": False, "mode": "failures", "dir": self.tee_dir},
            "truncate": {"max_lines": 500, "max_line_chars": 300},
        }

    def capture(self, fn, *args, **kwargs):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = fn(*args, **kwargs)
        return rc, out.getvalue(), err.getvalue()

    def run_mocked(self, completed, fn, *args, **kwargs):
        with mock.patch(
            "actx_lib.runner.subprocess.run", return_value=completed
        ) as spawn:
            result = self.capture(fn, *args, **kwargs)
        self.spawn = spawn
        return result

    def execute_mocked(self, results, fn, *args):
        side_effect = results if isinstance(results, list) else [results]
        with mock.patch("actx_lib.runner.execute", side_effect=side_effect):
            return self.capture(fn, *args)

    def tee_files(self):
        if not os.path.isdir(self.tee_dir):
            return []
        return sorted(
            os.path.join(self.tee_dir, name) for name in os.listdir(self.tee_dir)
        )

    def only_tee(self, err):
        """The single tee file: exists and is named on stderr."""
        files = self.tee_files()
        self.assertEqual(len(files), 1, files)
        self.assertIn("[full output: %s]" % files[0], err)
        with open(files[0], encoding="utf-8") as handle:
            return files[0], json.load(handle)


class RunContentTests(_Base):
    RAW = (
        synthetic_text().encode("utf-8")
        + b"crlf line\r\n"
        + b"bad \xff\xfe byte\n"
    )

    def capture_bytes(self, completed, cmd):
        """completed: a CompletedProcess, or an exception subprocess.run raises."""
        out = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
        err = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
        if isinstance(completed, BaseException):
            spawn = mock.patch("actx_lib.runner.subprocess.run", side_effect=completed)
        else:
            spawn = mock.patch("actx_lib.runner.subprocess.run", return_value=completed)
        with spawn:
            with mock.patch("sys.stdout", out), mock.patch("sys.stderr", err):
                rc = runner.run_content(cmd, self.config)
        out.flush()
        err.flush()
        return rc, out.buffer.getvalue(), err.buffer.getvalue()

    def test_bytes_identical_without_secret_any_exit(self):
        stderr = b"warn  \r\n\xff HTTP 401 Unauthorized\n"
        for code in (0, 1, 3):
            rc, out, err = self.capture_bytes(
                subprocess.CompletedProcess(["cat", "f"], code, self.RAW, stderr),
                ["cat", "f"],
            )
            self.assertEqual(rc, code)
            self.assertEqual(out, self.RAW)
            # No session hint line, no ANSI strip, no collapse, no cap.
            self.assertEqual(err, stderr)
        self.assertEqual(self.tee_files(), [])

    def test_secret_value_masked_every_other_byte_kept(self):
        raw = b"a\r\npassword=hunter2 user=bob\n\xff\n"
        rc, out, err = self.capture_bytes(
            subprocess.CompletedProcess(["cat", "f"], 0, raw, b"token=abc\n"),
            ["cat", "f"],
        )
        self.assertEqual(rc, 0)
        mask = MASK.encode("utf-8")
        self.assertEqual(out, b"a\r\npassword=" + mask + b" user=bob\n\xff\n")
        self.assertEqual(err, b"token=" + mask + b"\n")

    def test_exec_failure_maps_like_a_shell(self):
        rc, out, err = self.capture_bytes(
            FileNotFoundError(2, "No such file"), ["nosuch", "x"]
        )
        self.assertEqual((rc, out, err), (127, b"", b"nosuch: command not found\n"))
        rc, out, err = self.capture_bytes(
            PermissionError(13, "denied"), ["./script", "x"]
        )
        self.assertEqual((rc, out, err), (126, b"", b"./script: Permission denied\n"))

    def test_never_wrap_refused_without_execution(self):
        with mock.patch(
            "actx_lib.runner.hang_policy.classify", return_value="never_wrap"
        ):
            rc, out, err = self.run_mocked(
                None, runner.run_content, ["tail", "-f", "log"], self.config
            )
        self.assertEqual(rc, runner.NEVER_WRAP_EXIT_CODE)
        self.spawn.assert_not_called()


class RunLosslessTests(_Base):
    def test_exec_failure_maps_like_a_shell(self):
        # tee.mode=failures is on: the exec failure is actx's own message,
        # nothing to recover, so no tee file either.
        self.config["tee"]["enabled"] = True
        with mock.patch(
            "actx_lib.runner.subprocess.run",
            side_effect=FileNotFoundError(2, "No such file"),
        ):
            rc, out, err = self.capture(
                runner.run_lossless, ["tree", "-L", "2"], self.config
            )
        self.assertEqual(rc, 127)
        self.assertEqual(out, "")
        self.assertEqual(err, "tree: command not found\n")
        self.assertEqual(self.tee_files(), [])
        with mock.patch(
            "actx_lib.runner.subprocess.run",
            side_effect=PermissionError(13, "denied"),
        ):
            rc, out, err = self.capture(
                runner.run_lossless, ["/no/such/bin", "ps"], self.config
            )
        self.assertEqual(rc, 126)
        self.assertEqual(err, "/no/such/bin: Permission denied\n")

    def test_log_form_uncapped_collapsed_ansi_stripped_masked(self):
        raw = synthetic_text() + "password=hunter2\n"
        stderr = "e\ne\n\x1b[1mbold\x1b[0m\n"
        rc, out, err = self.run_mocked(
            subprocess.CompletedProcess(["docker", "logs", "web"], 0, raw, stderr),
            runner.run_lossless, ["docker", "logs", "web"], self.config,
            cap=False, stderr=True,
        )
        self.assertEqual(rc, 0)
        expected = raw.replace("same\nsame\nsame\n", "same  [×3]\n")
        expected = expected.replace("\x1b[31mred\x1b[0m", "red")
        expected = expected.replace("hunter2", MASK)
        self.assertEqual(out, expected)
        self.assertEqual(err, "e  [×2]\nbold\n")
        self.assertEqual(self.tee_files(), [])

    def test_line_cap_cut_forces_tee_named_in_marker(self):
        raw = synthetic_text() + "password=hunter2\n"
        rc, out, err = self.run_mocked(
            subprocess.CompletedProcess(["cat", "f"], 0, raw, ""),
            runner.run_lossless, ["cat", "f"], self.config,
        )
        self.assertEqual(rc, 0)
        path, record = self.only_tee(err)
        self.assertIn("lines omitted — full output: %s]" % path, out)
        self.assertEqual(record["stdout"], redaction.redact_text(raw))
        self.assertEqual(record["exit_code"], 0)

    def test_char_clip_alone_forces_tee(self):
        raw = "short\n" + "y" * 400 + "\n"
        rc, out, err = self.run_mocked(
            subprocess.CompletedProcess(["cat", "f"], 0, raw, ""),
            runner.run_lossless, ["cat", "f"], self.config,
        )
        self.assertEqual(out, "short\n" + "y" * 300 + "...(truncated)\n")
        path, record = self.only_tee(err)
        self.assertEqual(record["stdout"], raw)

    def test_uncut_output_not_teed(self):
        rc, out, err = self.run_mocked(
            subprocess.CompletedProcess(["cat", "f"], 0, "a\nb\n", ""),
            runner.run_lossless, ["cat", "f"], self.config,
        )
        self.assertEqual((rc, out, err), (0, "a\nb\n", ""))
        self.assertEqual(self.tee_files(), [])

    def test_json_printed_as_masked_raw_text(self):
        # One line far over the char cap, duplicate keys, non-ASCII: any
        # json.dumps or cap would change these bytes.
        raw = '{"a": "%s", "a": 1, "password": "hunter2"}' % ("é" * 5000)
        rc, out, err = self.run_mocked(
            subprocess.CompletedProcess(["bq", "show"], 0, raw, ""),
            runner.run_lossless, ["bq", "show"], self.config,
        )
        self.assertEqual(out, redaction.redact_text(raw) + "\n")
        self.assertNotIn("hunter2", out)
        json.loads(out)
        self.assertEqual(self.tee_files(), [])

    def test_stderr_false_leaves_stderr_off_screen(self):
        rc, out, err = self.run_mocked(
            subprocess.CompletedProcess(["x"], 0, "out\n", "noise\n"),
            runner.run_lossless, ["x"], self.config, stderr=False,
        )
        self.assertEqual((out, err), ("out\n", ""))

    def test_tee_oserror_one_warning_output_once(self):
        blocker = os.path.join(self.home, "file")
        with open(blocker, "w", encoding="utf-8") as handle:
            handle.write("x")
        self.config["tee"]["dir"] = os.path.join(blocker, "tee")
        raw = synthetic_text()
        rc, out, err = self.run_mocked(
            subprocess.CompletedProcess(["cat", "f"], 0, raw, ""),
            runner.run_lossless, ["cat", "f"], self.config,
        )
        self.assertEqual(rc, 0)
        self.assertEqual(out.count("line 0000\t"), 1)
        self.assertEqual(err.count("[actx] tee write failed"), 1)
        self.assertNotIn("[full output", err)
        self.assertIn("lines omitted — сузьте команду]", out)

    def test_policy_tee_oserror_does_not_duplicate_output(self):
        # tee.mode=always on an uncut output: a failing write used to fall
        # through to raw_fallback and print everything a second time.
        blocker = os.path.join(self.home, "file")
        with open(blocker, "w", encoding="utf-8") as handle:
            handle.write("x")
        self.config["tee"] = {
            "enabled": True, "mode": "always",
            "dir": os.path.join(blocker, "tee"),
        }
        rc, out, err = self.run_mocked(
            subprocess.CompletedProcess(["cat", "f"], 0, "a\n", ""),
            runner.run_lossless, ["cat", "f"], self.config,
        )
        self.assertEqual((rc, out), (0, "a\n"))
        self.assertEqual(err.count("[actx] tee write failed"), 1)

    def test_write_tee_never_prints_none(self):
        result = subprocess.CompletedProcess(["x"], 1, "o\n", "e\n")
        with mock.patch("actx_lib.runner._write_tee", return_value=None):
            rc, out, err = self.capture(
                runner.write_tee, ["x"], result, self.config
            )
        self.assertEqual(err, "")


class RunGenericTests(_Base):
    def test_failing_exit_prints_stdout_in_lossless_form(self):
        stdout = "\x1b[32mok\x1b[0m\nok\npassword=hunter2\n"
        rc, out, err = self.run_mocked(
            subprocess.CompletedProcess(["tool", "get"], 2, stdout, "boom\n"),
            runner.run, ["tool", "get"], self.config,
        )
        self.assertEqual(rc, 2)
        self.assertEqual(out, "ok  [×2]\npassword=%s\n" % MASK)
        self.assertEqual(err, "boom\n[exit: 2]\n")
        self.assertEqual(self.tee_files(), [])

    def test_failing_exit_cap_cut_forces_tee(self):
        raw = synthetic_text()
        rc, out, err = self.run_mocked(
            subprocess.CompletedProcess(["tool", "get"], 1, raw, "boom\n"),
            runner.run, ["tool", "get"], self.config,
        )
        self.assertEqual(rc, 1)
        path, record = self.only_tee(err)
        self.assertIn("full output: %s]" % path, out)
        self.assertEqual(record["stdout"], raw)
        self.assertEqual(record["exit_code"], 1)

    def test_success_json_printed_whole_even_with_long_array(self):
        raw = json.dumps({"items": list(range(1000)), "token": "abc"})
        rc, out, err = self.run_mocked(
            subprocess.CompletedProcess(["tool", "get"], 0, raw, ""),
            runner.run, ["tool", "get"], self.config,
        )
        self.assertEqual(out, redaction.redact_text(raw) + "\n")
        self.assertEqual(json.loads(out)["items"], list(range(1000)))


class CompactedResultTests(_Base):
    def compact(self, stdout, compact_fn, rc=0):
        result = subprocess.CompletedProcess(["tool"], rc, stdout, "")
        return self.capture(
            runner.compacted_result, ["tool"], result, self.config, compact_fn
        )

    def test_empty_compactor_prints_lossless_form(self):
        for empty in ("", "  \n"):
            rc, out, err = self.compact(
                "a\na\n\x1b[1mb\x1b[0m\npassword=hunter2\n", lambda r: empty
            )
            self.assertEqual(rc, 0)
            self.assertEqual(out, "a  [×2]\nb\npassword=%s\n" % MASK)

    def test_empty_compactor_cut_forces_tee(self):
        raw = synthetic_text()
        rc, out, err = self.compact(raw, lambda r: "", rc=1)
        self.assertEqual(rc, 1)
        path, record = self.only_tee(err)
        self.assertIn("full output: %s]" % path, out)
        self.assertEqual(record["stdout"], raw)

    def test_failures_mode_green_run_stays_silent(self):
        # Guard (green at HEAD too): the one exception to never-empty.
        passing = "tests/test_a.py ..\n\n===== 2 passed in 0.01s =====\n"
        rc, out, err = self.execute_mocked(
            subprocess.CompletedProcess(["pytest"], 0, passing, ""),
            test_runner_filter.run_failures, ["pytest"], self.config,
        )
        self.assertEqual((rc, out), (0, ""))


class StdoutSurvivesNonZeroExitTests(_Base):
    def test_find_partial_results_shown(self):
        rc, out, err = self.execute_mocked(
            subprocess.CompletedProcess(
                ["find", "."], 1, "./a\n./b\n", "find: ./x: Permission denied\n"
            ),
            system_filter.run_find, ["."], self.config,
        )
        self.assertEqual(rc, 1)
        self.assertEqual(out, "./a\n./b\n")
        self.assertEqual(err, "find: ./x: Permission denied\n")

    def test_git_failure_shows_stdout(self):
        rc, out, err = self.execute_mocked(
            subprocess.CompletedProcess(
                ["git", "log"], 128, "abc1234 msg\n", "fatal: bad\n"
            ),
            git_filter.run, ["log"], self.config,
        )
        self.assertEqual((rc, out, err), (128, "abc1234 msg\n", "fatal: bad\n"))

    def test_read_failure_shows_stdout(self):
        rc, out, err = self.execute_mocked(
            subprocess.CompletedProcess(["cat", "f.py"], 1, "partial\n", "err\n"),
            read_filter.run, ["f.py", "--level", "minimal"], self.config,
        )
        self.assertEqual((rc, out, err), (1, "partial\n", "err\n"))

    def test_smart_failure_shows_stdout(self):
        rc, out, err = self.execute_mocked(
            subprocess.CompletedProcess(["cat", "f.py"], 1, "partial\n", "err\n"),
            smart_filter.run, ["f.py"], self.config,
        )
        self.assertEqual((rc, out, err), (1, "partial\n", "err\n"))

    def test_read_all_comments_never_empty(self):
        text = "# only\n# comments\n"
        rc, out, err = self.execute_mocked(
            subprocess.CompletedProcess(["cat", "f.py"], 0, text, ""),
            read_filter.run, ["f.py", "--level", "minimal"], self.config,
        )
        self.assertEqual((rc, out), (0, text))


class ListingTeeTests(_Base):
    def make_dir(self, count):
        work = tempfile.mkdtemp(dir=self.home)
        for index in range(count):
            with open(os.path.join(work, "file_%03d.txt" % index), "w") as handle:
                handle.write("x")
        return work

    def test_ls_summary_omitting_entries_tees_full_listing(self):
        work = self.make_dir(40)
        rc, out, err = self.capture(system_filter.run_ls, [work], self.config)
        self.assertEqual(rc, 0)
        self.assertIn("  ... (30 more)", out)
        raw = subprocess.run(
            ["ls", "-1", work], capture_output=True, text=True
        ).stdout
        path, record = self.only_tee(err)
        self.assertEqual(record["stdout"], redaction.redact_text(raw))

    def test_short_ls_not_teed(self):
        work = self.make_dir(5)
        rc, out, err = self.capture(system_filter.run_ls, [work], self.config)
        self.assertEqual((rc, err), (0, ""))
        self.assertEqual(self.tee_files(), [])

    def test_find_omitting_names_tees_raw(self):
        raw = "".join("./d/file_%02d.txt\n" % i for i in range(15))
        rc, out, err = self.execute_mocked(
            subprocess.CompletedProcess(["find", "."], 0, raw, ""),
            system_filter.run_find, ["."], self.config,
        )
        self.assertIn("  ... (5 more)", out)
        path, record = self.only_tee(err)
        self.assertEqual(record["stdout"], raw)

    def test_find_pure_reformat_not_teed(self):
        raw = "".join(
            "./dir_%d/a_rather_long_file_name_%02d.txt\n" % (d, i)
            for d in range(3) for i in range(4)
        )
        self.assertGreater(len(raw), 200)
        rc, out, err = self.execute_mocked(
            subprocess.CompletedProcess(["find", "."], 0, raw, ""),
            system_filter.run_find, ["."], self.config,
        )
        self.assertEqual((rc, err), (0, ""))
        self.assertEqual(self.tee_files(), [])

    def test_git_status_group_cut_tees_porcelain(self):
        porcelain = "".join(" M f%03d.py\n" % i for i in range(205))
        rc, out, err = self.execute_mocked(
            [
                subprocess.CompletedProcess(["git"], 0, porcelain, ""),
                subprocess.CompletedProcess(["git"], 0, "main\n", ""),
            ],
            git_filter.run, ["status"], self.config,
        )
        self.assertEqual(rc, 0)
        self.assertIn("  ... (5 more)", out)
        path, record = self.only_tee(err)
        self.assertEqual(record["stdout"], porcelain)

    def test_tree_walk_cap_tees_full_walk(self):
        work = self.make_dir(205)
        rc, out, err = self.capture(tree_filter.run, [work], self.config)
        self.assertEqual(rc, 0)
        self.assertEqual(len(out.strip().split("\n")), 200)
        self.assertTrue(out.rstrip().endswith("... (7 more)"))
        full = [work + " (205)"] + ["  file_%03d.txt" % i for i in range(205)]
        path, record = self.only_tee(err)
        self.assertEqual(record["stdout"], "\n".join(full) + "\n")

    def test_short_tree_not_teed(self):
        work = self.make_dir(3)
        rc, out, err = self.capture(tree_filter.run, [work], self.config)
        self.assertEqual((rc, err), (0, ""))
        self.assertEqual(self.tee_files(), [])


class TreeBinaryTests(_Base):
    def test_flags_and_multiple_paths_run_the_real_tree(self):
        for args, code in ((["-L", "2"], 0), (["a", "b"], 2), (["-X"], 0)):
            listing = ".\n└── a\n"
            rc, out, err = self.run_mocked(
                subprocess.CompletedProcess(["tree"] + args, code, listing, ""),
                tree_filter.run, args, self.config,
            )
            self.assertEqual(rc, code)
            self.assertEqual(out, listing)
            self.assertEqual(self.spawn.call_args[0][0], ["tree"] + args)

    def test_missing_tree_binary_is_127(self):
        with mock.patch(
            "actx_lib.runner.subprocess.run",
            side_effect=FileNotFoundError(2, "No such file"),
        ):
            rc, out, err = self.capture(tree_filter.run, ["-L", "2"], self.config)
        self.assertEqual((rc, out, err), (127, "", "tree: command not found\n"))


if __name__ == "__main__":
    unittest.main()
