import json
import os
import subprocess
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACTX = os.path.join(ROOT, "actx")

HOOK_JSON = json.dumps({"tool_name": "Bash", "tool_input": {"command": "git status"}})

# PRD.md section 13.10 targets, with the documented 3x flake tolerance.
HOOK_LIMIT = 0.030 * 3
REWRITE_LIMIT = 0.030 * 3
OVERHEAD_LIMIT = 0.040 * 3
FILTER_10MB_LIMIT = 2.0 * 3


def _median(samples):
    ordered = sorted(samples)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2.0


def _time_command(cmd, **kwargs):
    start = time.perf_counter()
    subprocess.run(cmd, capture_output=True, text=True, **kwargs)
    return time.perf_counter() - start


class PerfTests(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.TemporaryDirectory()
        self.env = os.environ.copy()
        self.env["HOME"] = self.home.name

    def tearDown(self):
        self.home.cleanup()

    def _median_actx(self, args, **kwargs):
        samples = [_time_command([ACTX] + args, env=self.env, **kwargs) for _ in range(5)]
        return _median(samples)

    @staticmethod
    def _gate_ms(command, batch):
        """Per-op ms of the in-memory gate (TK-63): min of 5 batch means of
        process CPU time. CPU time leaves out the time this process waits
        for a core on a loaded machine, and the minimum drops a batch hit by
        cache or frequency noise; the threshold itself is unchanged."""
        from actx_lib import security_gate

        best = None
        for _ in range(5):
            start = time.process_time()
            for _ in range(batch):
                security_gate.evaluate_security(command)
            per_op_ms = (time.process_time() - start) / batch * 1000.0
            best = per_op_ms if best is None else min(best, per_op_ms)
        return best

    def test_security_gate_in_memory_under_1ms(self):
        cases = (
            ("baseline", "git status", 1000),
            ("large 4005-char", "echo " + ("a" * 4000), 200),
            ("compound 90-chunk", ";".join(["true" for _ in range(90)]), 200),
            (
                "wide 150-file",
                "grep -rn 'TODO' " + " ".join([f"src/m{i}/f{i}.py" for i in range(150)]),
                200,
            ),
        )
        for name, command, batch in cases:
            ms = self._gate_ms(command, batch)
            self.assertLess(ms, 1.0, "%s command evaluation %.4fms per op" % (name, ms))

    def test_security_gate_adversarial_inline_socket_under_1ms(self):
        """TK-63: repeated interpreter/flag words once took 46 ms - 3 s in
        the single backtracking socket regex. Each case contains '/' (no
        >200-char fast path) and stays <= 4096 chars (no length guard), and
        a counter proves the staged socket search is reached."""
        from unittest import mock

        from actx_lib.security_gate import t2_t3

        def adversarial(unit):
            command = "/x "
            while len(command) + len(unit) <= 4096:
                command += unit
            return command

        for unit in ("python3 -c x ", "python -c ", "node -e "):
            command = adversarial(unit)
            self.assertLessEqual(len(command), 4096)
            with mock.patch.object(
                t2_t3, "_inline_socket_search", wraps=t2_t3._inline_socket_search
            ) as staged:
                from actx_lib import security_gate

                security_gate.evaluate_security(command)
            self.assertGreaterEqual(staged.call_count, 1, unit)
            ms = self._gate_ms(command, 50)
            self.assertLess(ms, 1.0, "adversarial %r evaluation %.4fms per op" % (unit, ms))

    def test_hook_under_30ms(self):
        _time_command([ACTX, "hook"], input=HOOK_JSON, env=self.env)  # warm-up
        median = self._median_actx(["hook"], input=HOOK_JSON)
        self.assertLess(median, HOOK_LIMIT, "hook median %.4fs" % median)

    def test_rewrite_under_30ms(self):
        _time_command([ACTX, "rewrite", "git status"], env=self.env)  # warm-up
        median = self._median_actx(["rewrite", "git status"])
        self.assertLess(median, REWRITE_LIMIT, "rewrite median %.4fs" % median)

    def test_git_status_overhead_under_40ms(self):
        with tempfile.TemporaryDirectory() as repo:
            def git(*args):
                return subprocess.run(
                    ["git", "-C", repo] + list(args),
                    capture_output=True,
                    text=True,
                )

            git("init", "-q")
            git("config", "user.email", "a@b.c")
            git("config", "user.name", "tester")
            with open(os.path.join(repo, "f"), "w", encoding="utf-8") as handle:
                handle.write("a\n")
            git("add", "f")
            git("commit", "-m", "init")

            def raw_time():
                return _time_command(["git", "status"], cwd=repo, env=self.env)

            def actx_time():
                return _time_command([ACTX, "git", "status"], cwd=repo, env=self.env)

            raw_time()  # warm-up
            actx_time()  # warm-up
            raw_median = _median([raw_time() for _ in range(5)])
            actx_median = _median([actx_time() for _ in range(5)])
            overhead = actx_median - raw_median
            self.assertLess(
                overhead,
                OVERHEAD_LIMIT,
                "git status overhead %.4fs (actx %.4fs, raw %.4fs)"
                % (overhead, actx_median, raw_median),
            )

    def test_10mb_output_filtering_under_2s(self):
        with tempfile.TemporaryDirectory() as work:
            big = os.path.join(work, "big.txt")
            line_template = "match line %06d\n"
            line_len = len(line_template % 123456)
            count = (10 * 1024 * 1024) // line_len
            with open(big, "w", encoding="utf-8") as handle:
                handle.write("".join(line_template % i for i in range(count)))

            start = time.perf_counter()
            proc = subprocess.run(
                [ACTX, "grep", "match", big],
                capture_output=True,
                text=True,
                cwd=work,
                env=self.env,
            )
            elapsed = time.perf_counter() - start

            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertLess(elapsed, FILTER_10MB_LIMIT, "filtering %.3fs" % elapsed)


if __name__ == "__main__":
    unittest.main()
