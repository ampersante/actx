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

    def test_security_gate_in_memory_under_1ms(self):
        from actx_lib import security_gate

        # 1000 in-memory evaluations of baseline command
        start = time.perf_counter()
        for _ in range(1000):
            security_gate.evaluate_security("git status")
        elapsed = time.perf_counter() - start
        per_op_ms = (elapsed / 1000.0) * 1000.0
        self.assertLess(per_op_ms, 1.0, "security_gate evaluation %.4fms per op" % per_op_ms)

        # 200 in-memory evaluations of large 4005-char command
        large_cmd = "echo " + ("a" * 4000)
        start = time.perf_counter()
        for _ in range(200):
            security_gate.evaluate_security(large_cmd)
        elapsed = time.perf_counter() - start
        large_ms = (elapsed / 200.0) * 1000.0
        self.assertLess(large_ms, 1.0, "large command evaluation %.4fms per op" % large_ms)

        # 200 in-memory evaluations of compound 90-chunk command
        compound_cmd = ";".join(["true" for _ in range(90)])
        start = time.perf_counter()
        for _ in range(200):
            security_gate.evaluate_security(compound_cmd)
        elapsed = time.perf_counter() - start
        compound_ms = (elapsed / 200.0) * 1000.0
        self.assertLess(compound_ms, 1.0, "compound command evaluation %.4fms per op" % compound_ms)

        # 200 in-memory evaluations of 150-file wide argument command (~2000 chars)
        wide_cmd = "grep -rn 'TODO' " + " ".join([f"src/m{i}/f{i}.py" for i in range(150)])
        start = time.perf_counter()
        for _ in range(200):
            security_gate.evaluate_security(wide_cmd)
        elapsed = time.perf_counter() - start
        wide_ms = (elapsed / 200.0) * 1000.0
        self.assertLess(wide_ms, 1.0, "wide 150-file command evaluation %.4fms per op" % wide_ms)

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
