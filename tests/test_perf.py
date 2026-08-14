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
