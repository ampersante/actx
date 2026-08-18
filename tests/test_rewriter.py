import os
import subprocess
import unittest

from actx_lib.rewriter import rewrite

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACTX = os.path.join(ROOT, "actx")


class RewriteUnitTests(unittest.TestCase):
    def test_git_status_rewritten(self):
        self.assertEqual(rewrite("git status"), "actx git status")

    def test_git_diff_rewritten(self):
        self.assertEqual(rewrite("git diff"), "actx git diff")

    def test_git_log_rewritten(self):
        self.assertEqual(rewrite("git log --oneline"), "actx git log --oneline")

    def test_git_alone_rejected(self):
        self.assertIsNone(rewrite("git"))

    def test_git_rm_still_rejected(self):
        self.assertIsNone(rewrite("git rm file"))

    def test_git_output_flag_rejected(self):
        self.assertIsNone(rewrite("git diff --output=x"))

    def test_git_output_equals_rejected(self):
        self.assertIsNone(rewrite("git diff --output=x"))

    def test_git_out_prefix_rejected(self):
        self.assertIsNone(rewrite("git diff --output=x"))

    def test_compound_command_rejected(self):
        self.assertIsNone(rewrite("git status && rm x"))

    def test_redirect_rejected(self):
        self.assertIsNone(rewrite("git status > /tmp/x"))

    def test_semicolon_rejected(self):
        self.assertIsNone(rewrite("grep 'foo;bar' x"))

    def test_ls_rewritten(self):
        self.assertEqual(rewrite("ls"), "actx ls")

    def test_ls_path_rewritten(self):
        self.assertEqual(rewrite("ls src"), "actx ls src")

    def test_ls_la_rewritten(self):
        self.assertEqual(rewrite("ls -la"), "actx ls -la")

    def test_ls_color_rejected(self):
        self.assertIsNone(rewrite("ls --color"))

    def test_ls_empty_arg_rejected(self):
        self.assertIsNone(rewrite('ls ""'))

    def test_ls_multiple_paths_rejected(self):
        self.assertIsNone(rewrite("ls a b"))

    def test_grep_rewritten(self):
        self.assertEqual(rewrite("grep foo file"), "actx grep foo file")

    def test_find_rewritten(self):
        self.assertEqual(rewrite("find . -name '*.py'"), "actx find . -name '*.py'")

    def test_find_delete_rejected(self):
        self.assertIsNone(rewrite("find . -delete"))

    def test_find_exec_rejected(self):
        self.assertIsNone(rewrite("find . -exec rm {} \\;"))

    def test_git_show_rewritten(self):
        self.assertEqual(rewrite("git show HEAD"), "actx git show HEAD")

    def test_git_blame_rewritten(self):
        self.assertEqual(rewrite("git blame file"), "actx git blame file")

    def test_git_branch_ro_rewritten(self):
        self.assertEqual(rewrite("git branch -a"), "actx git branch -a")

    def test_git_branch_delete_rejected(self):
        self.assertIsNone(rewrite("git branch -d x"))

    def test_git_add_rewritten(self):
        self.assertEqual(rewrite("git add ."), "actx git add .")

    def test_rg_rewritten(self):
        self.assertEqual(rewrite("rg foo"), "actx rg foo")

    def test_cat_rewritten(self):
        self.assertEqual(rewrite("cat README.md"), "actx cat README.md")

    def test_tree_rewritten(self):
        self.assertEqual(rewrite("tree"), "actx tree")

    def test_gh_pr_rewritten(self):
        self.assertEqual(rewrite("gh pr list"), "actx gh pr list")

    def test_pytest_rewritten(self):
        self.assertEqual(rewrite("pytest -q"), "actx pytest -q")

    def test_ruff_fix_rejected(self):
        self.assertIsNone(rewrite("ruff check --fix"))

    def test_ruff_format_rejected(self):
        self.assertIsNone(rewrite("ruff format ."))

    def test_docker_ps_rewritten(self):
        self.assertEqual(rewrite("docker ps"), "actx docker ps")

    def test_docker_run_rejected(self):
        self.assertIsNone(rewrite("docker run x"))

    def test_kubectl_apply_rejected(self):
        self.assertIsNone(rewrite("kubectl apply -f f"))

    def test_pip_install_rewritten(self):
        self.assertEqual(rewrite("pip install x"), "actx pip install x")

    def test_npm_install_rewritten(self):
        self.assertEqual(rewrite("npm install"), "actx npm install")

    def test_aws_rejected(self):
        self.assertIsNone(rewrite("aws s3 ls"))

    def test_find_fprint_rejected(self):
        self.assertIsNone(rewrite("find . -fprint out.txt"))

    def test_find_print0_rewritten(self):
        self.assertEqual(rewrite("find . -print0"), "actx find . -print0")

    def test_wc_rewritten(self):
        self.assertEqual(rewrite("wc -l tasks.md"), "actx wc -l tasks.md")

    def test_head_rewritten(self):
        self.assertEqual(rewrite("head -20 tasks.md"), "actx head -20 tasks.md")

    def test_tail_follow_rejected(self):
        self.assertIsNone(rewrite("tail -f x"))

    def test_sort_output_rejected(self):
        self.assertIsNone(rewrite("sort -o out in"))

    def test_uniq_rewritten(self):
        self.assertEqual(rewrite("uniq -c tasks.md"), "actx uniq -c tasks.md")

    def test_python_script_rejected(self):
        self.assertIsNone(rewrite("python3 parse.py"))

    def test_python_c_rejected(self):
        self.assertIsNone(rewrite("python3 -c print(1)"))

    def test_unknown_command_rejected(self):
        self.assertIsNone(rewrite("echo hi"))

    def test_empty_rejected(self):
        self.assertIsNone(rewrite(""))

    def test_whitespace_only_rejected(self):
        self.assertIsNone(rewrite("   "))

    def test_actx_prefix_idempotent(self):
        self.assertIsNone(rewrite("actx git status"))

    def test_over_4096_rejected(self):
        self.assertIsNone(rewrite("grep " + "a" * 4096))

    def test_newline_rejected(self):
        self.assertIsNone(rewrite("ls\nrm -rf /"))

    def test_dollar_rejected(self):
        self.assertIsNone(rewrite("ls $HOME"))

    def test_backtick_rejected(self):
        self.assertIsNone(rewrite("ls `id`"))

    def test_parens_rejected(self):
        self.assertIsNone(rewrite("echo $(whoami)"))

    def test_unclosed_quote_rejected(self):
        self.assertIsNone(rewrite("git status '"))

    def test_verbatim_preserves_quoting(self):
        self.assertEqual(rewrite("grep 'foo bar' file"), "actx grep 'foo bar' file")


class RewriteCliTests(unittest.TestCase):
    def run_actx(self, args):
        return subprocess.run(
            [ACTX] + args, capture_output=True, text=True
        )

    def test_rewrite_git_status(self):
        p = self.run_actx(["rewrite", "git status"])
        self.assertEqual(p.returncode, 0)
        self.assertEqual(p.stdout, "actx git status\n")
        self.assertEqual(p.stderr, "")

    def test_rewrite_compound_empty(self):
        p = self.run_actx(["rewrite", "git status && rm x"])
        self.assertEqual(p.returncode, 0)
        self.assertEqual(p.stdout, "")
        self.assertEqual(p.stderr, "")

    def test_rewrite_git_alone_empty(self):
        p = self.run_actx(["rewrite", "git"])
        self.assertEqual(p.returncode, 0)
        self.assertEqual(p.stdout, "")

    def test_rewrite_find_delete_empty(self):
        p = self.run_actx(["rewrite", "find . -delete"])
        self.assertEqual(p.returncode, 0)
        self.assertEqual(p.stdout, "")

    def test_rewrite_git_diff_output_empty(self):
        p = self.run_actx(["rewrite", "git diff --output=x"])
        self.assertEqual(p.returncode, 0)
        self.assertEqual(p.stdout, "")

    def test_rewrite_ls_empty_arg_empty(self):
        p = self.run_actx(["rewrite", 'ls ""'])
        self.assertEqual(p.returncode, 0)
        self.assertEqual(p.stdout, "")

    def test_rewrite_grep_semicolon_empty(self):
        p = self.run_actx(["rewrite", "grep 'foo;bar' x"])
        self.assertEqual(p.returncode, 0)
        self.assertEqual(p.stdout, "")

    def test_rewrite_over_4096_empty(self):
        p = self.run_actx(["rewrite", "grep " + "a" * 4096])
        self.assertEqual(p.returncode, 0)
        self.assertEqual(p.stdout, "")

    def test_rewrite_empty_empty(self):
        p = self.run_actx(["rewrite", ""])
        self.assertEqual(p.returncode, 0)
        self.assertEqual(p.stdout, "")

    def test_rewrite_invalid_empty(self):
        p = self.run_actx(["rewrite", "git status '"])
        self.assertEqual(p.returncode, 0)
        self.assertEqual(p.stdout, "")

    def test_rewrite_missing_argument_empty(self):
        p = self.run_actx(["rewrite"])
        self.assertEqual(p.returncode, 0)
        self.assertEqual(p.stdout, "")

    def test_rewrite_extra_argument_exit_1(self):
        p = self.run_actx(["rewrite", "git status", "extra"])
        self.assertEqual(p.returncode, 1)
        self.assertEqual(p.stdout, "")
        self.assertNotEqual(p.stderr, "")

    def test_run_echo(self):
        p = self.run_actx(["run", "echo", "hi"])
        self.assertEqual(p.returncode, 0)
        self.assertEqual(p.stdout, "hi\n")

    def test_unknown_subcommand_exit_1(self):
        p = self.run_actx(["not-a-command"])
        self.assertEqual(p.returncode, 1)
        self.assertNotEqual(p.stderr, "")


if __name__ == "__main__":
    unittest.main()
