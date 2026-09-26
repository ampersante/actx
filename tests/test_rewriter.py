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
        # TK-55 F2: gh dispatch is generated from cli_families ro_verbs.
        self.assertEqual(rewrite("gh pr list"), "actx gh pr list")

    def test_gh_ro_verbs_rewritten(self):
        for command in (
            "gh pr list",
            "gh pr view 3",
            "gh pr diff 3",
            "gh issue list",
            "gh run list",
            "gh run view 1",
            "gh repo list",
        ):
            with self.subTest(command=command):
                self.assertEqual(rewrite(command), "actx " + command)

    def test_gh_mutating_streaming_and_secret_not_rewritten(self):
        # TK-55 F2: ask-class mutations, streaming verbs, file-download
        # and credential surfaces all stay unrewritten (defer/never-wrap
        # is decided by gate/hang-policy layers, not the rewriter).
        for command in (
            "gh pr merge 1",
            "gh issue create",
            "gh run delete 1",
            "gh run download 1",
            "gh run watch",
            "gh auth token",
            "gh api repos",
        ):
            with self.subTest(command=command):
                self.assertIsNone(rewrite(command))

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

    def test_docker_ro_verbs_rewritten(self):
        # TK-41: docker dispatch is generated from cli_families ro_verbs.
        for command in (
            "docker ps",
            "docker images",
            "docker logs web",
            "docker inspect c",
            "docker system df",
            "docker stats --no-stream",
            "docker compose ps",
            "docker compose logs web",
        ):
            with self.subTest(command=command):
                self.assertEqual(rewrite(command), "actx " + command)

    def test_docker_non_ro_verbs_not_rewritten(self):
        for command in (
            "docker stats",
            "docker compose up",
            "docker compose up -d",
            "docker rm x",
            "docker rmi x",
            "docker system prune",
            "docker volume rm x",
            "docker volume prune",
            "docker exec x ls",
        ):
            with self.subTest(command=command):
                self.assertIsNone(rewrite(command))

    def test_docker_global_value_flag_not_skipped(self):
        # global_flags is empty: the scan stops at --context (conservative),
        # and compose-level flags defeat the ("compose", "ps") prefix.
        self.assertIsNone(rewrite("docker --context prod ps"))
        self.assertIsNone(rewrite("docker compose -f x.yml ps"))

    def test_kubectl_apply_rejected(self):
        self.assertIsNone(rewrite("kubectl apply -f f"))

    def test_pip_install_not_rewritten(self):
        # TK-51 (2026-09-05): installs left the mutator allow-list — the
        # T5 gate asks instead; the rewriter must not touch them.
        self.assertIsNone(rewrite("pip install x"))

    def test_uv_pip_install_not_rewritten(self):
        self.assertIsNone(rewrite("uv pip install x"))

    def test_npm_install_not_rewritten(self):
        self.assertIsNone(rewrite("npm install"))
        self.assertIsNone(rewrite("npm install lodash"))
        self.assertIsNone(rewrite("pnpm add express"))

    def test_npm_list_rewritten(self):
        self.assertEqual(rewrite("npm list"), "actx npm list")

    def test_pip_list_rewritten(self):
        self.assertEqual(rewrite("pip list"), "actx pip list")

    def test_uv_run_rewritten(self):
        self.assertEqual(rewrite("uv run pytest"), "actx uv run pytest")

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

    def test_denied_write_flags_rejected(self):
        # TK-55 F3: a flag whose value is a write path / output redirect
        # defeats rewriting on every listed RO head (eq / attached /
        # prefix match kinds, separate-value and `=`-forms).
        for command in (
            "tree -o /tmp/x",
            "tree -o/tmp/x",
            "sort -o out in",
            "sort --output=out in",
            "jest --outputFile=/tmp/x",
            "jest --outputFile /tmp/x",
            "jest --coverageDirectory /tmp/x",
            "vitest --outputFile=x",
            "eslint -o /tmp/x .",
            "eslint -o/tmp/x .",
            "eslint --output-file /tmp/x .",
            "ruff check --output-file /tmp/x .",
            "ruff check -o /tmp/x .",
            "ruff check --cache-dir /tmp/x .",
            "go test -coverprofile=/tmp/x ./...",
            "go test -o /tmp/x ./...",
            "go test -c -o /tmp/x ./...",
            "go test -trace /tmp/x ./...",
            "tsc --outFile /tmp/x a.ts",
            "tsc --outDir /tmp/x a.ts",
            "tsc --out /tmp/x.js a.ts",
            "tsc --tsBuildInfoFile /tmp/x a.ts",
            "pytest --junitxml=/tmp/x",
            "pytest --junit-xml=/tmp/x",
            "pytest --basetemp /tmp/x",
            "git diff --output=x",
            "git diff --output /tmp/x",
            # Acceptance findings: alternate spellings that still write.
            "tree --output /tmp/x",
            "tree --output=/tmp/x",
            "jest --output-file /tmp/x",          # yargs dashed→camel map
            "jest --coverage-directory /tmp/x",
            "vitest --outputFile.json=/tmp/x",    # dotted reporter form
            "tsc --outfile /tmp/x a.ts",          # tsc is case-insensitive
            "tsc --OUTDIR /tmp/x a.ts",
            "tsc --declarationdir=/tmp/x a.ts",
            # Re-acceptance F-A/F-B: dash-count and case equivalences.
            "go test --coverprofile=/tmp/x ./...",   # go flag pkg: -- ≡ -
            "go test --o=/tmp/x ./...",
            "go test --c ./...",
            "go test --trace=/tmp/x ./...",
            "go test --outputdir /tmp/x ./...",
            "tsc -outdir /tmp/x a.ts",               # tsc: 1-2 dashes, CI
            "tsc -outFile /tmp/x a.ts",
            "tsc -generateTrace /tmp/x a.ts",
            "tsc -tsbuildinfofile /tmp/x a.ts",
            "eslint --outp /tmp/x .",                # optionator abbrev
            "eslint --o /tmp/x .",                   # optionator: any prefix
            "eslint --out /tmp/x .",
            "sort --o /tmp/x in",                    # getopt_long abbrev
            "sort --out=/tmp/x in",
            "vitest --output-file=/tmp/x",
            "pytest --junitx=/tmp/x",                # argparse abbrev
            "pytest --junit-x=/tmp/x",
            "pytest --baset /tmp/x",
            # Re-acceptance round 4: test.-prefix + residual exec/write flags.
            "go test -test.coverprofile=/tmp/x ./...",  # test-binary prefix
            "go test --test.outputdir /tmp/x ./...",
            "vitest --output-file.json=/tmp/x",
            "tree --out /tmp/x",                        # GNU abbrev
            "rg --pre rm pattern",                      # exec per file
            "rg --pre-glob='*.sh' rm pattern",
            "rg --hostname-bin=/tmp/x pattern",         # exec for hostname
            "psql -o /tmp/x -c 'select 1'",             # writes query output
            "psql --o=/tmp/x -c 'select 1'",
            "psql -L /tmp/x -c 'select 1'",             # --log-file
            "psql --log-file=/tmp/x -c 'select 1'",
            "psql --lo /tmp/x -c 'select 1'",
            "tail --f /var/log/syslog",                 # abbrev of --follow
            "tail --fol=name /var/log/syslog",
            "tail -F /var/log/syslog",
            # Round 5: smuggled payloads, positional writes, flag writes.
            "sqlite3 :memory: -cmd '.shell id' 'select 1'",  # meta exec
            "sqlite3 :memory: -cmd '.output /tmp/x' 'select 1'",
            "sqlite3 :memory: -cmd '.read /tmp/x' 'select 1'",
            "duckdb -cmd '.shell id' -c 'select 1'",
            "uniq /tmp/in /tmp/out",                      # positional output
            "uniq -c /tmp/in /tmp/out",
            "helm template --output-dir /tmp/x mychart",
            "helm template --output-dir=/tmp/x mychart",
            "helm template --post-renderer=/tmp/x.sh mychart",
            "helm template --post-renderer /tmp/x.sh mychart",
            "sort --compress-program=/tmp/x in",        # GNU exec on spill
            "sort --compress-program /tmp/x in",
            "terraform plan -out /tmp/x",
            "terraform plan -out=/tmp/x",
            # Round 7: source-mutation flags (the --fix sibling class).
            "jest -u",                              # inline snapshot rewrite
            "jest --updateSnapshot",
            "jest --update-snapshot",
            "vitest -u",
            "vitest --update",
            "ruff check --add-noqa .",              # rewrites sources
            "tsc --init",                           # writes tsconfig.json
            "tsc -init",
            # Round 8: swiftlint/swiftformat write flags (doc-cited).
            "swiftlint lint --autocorrect",         # alias of --fix
            "swiftlint lint --output /tmp/x",
            "swiftlint lint --write-baseline /tmp/x",
            "swiftlint lint --benchmark",
            "swiftformat --lint --report /tmp/x .",
        ):
            with self.subTest(command=command):
                self.assertIsNone(rewrite(command))

    def test_denied_write_flags_inside_run_prefix(self):
        # TK-55 F3: the inner head of `uv run <argv>` is the one matched.
        for command in (
            "uv run tsc --outFile ~/.zshrc",
            "uv run tree -o x",
            "uv run ruff --output-file=x .",
            "uv run -- tsc --outFile /tmp/x",     # behind `--` separator
        ):
            with self.subTest(command=command):
                self.assertIsNone(rewrite(command))

    def test_uv_run_unparseable_inner_defers(self):
        # TK-55 acceptance: rewriter must not auto-approve a `uv run`
        # whose inner command cannot be located (unknown flag, bare run).
        for command in (
            "uv run --unknown-flag rm -rf ~",
            "uv run --unknown-flag pytest",
            "uv run",
        ):
            with self.subTest(command=command):
                self.assertIsNone(rewrite(command))

    def test_denied_write_flags_false_positive_pins(self):
        # TK-55 F3: look-alike but RO forms must keep rewriting —
        # `go test -count=1` (no attached short forms in go's flag pkg),
        # `jest -o` = --onlyChanged, and plain RO invocations.
        for command in (
            "tree",
            "sort -u",
            "git diff",
            "jest",
            "jest -o",
            "vitest run",
            "eslint .",
            "ruff check .",
            "go test ./...",
            "go test -count=1 ./...",
            "go test --count=1 ./...",
            "go test -run X ./...",
            "go test -args -o x",      # -o after -args belongs to the binary
            "tsc --noEmit",
            "tsc --project .",
            "pytest -q",
            "pytest --junit-prefix x", # RO string flag, not a write path
            "uniq -c /tmp/in",               # single positional
            "uniq -f 2 /tmp/in",             # value-flag not a positional
            "uniq --skip-fields=2 /tmp/in",
            "helm list --output json",       # RO format flag
            "sqlite3 :memory: -cmd 'select 1'",  # RO -cmd payload
            "swiftlint lint .",                  # plain RO lint
            "swiftformat --lint .",              # --output inert in lint
            "uv run pytest",
            "uv run --with requests pytest",
        ):
            with self.subTest(command=command):
                self.assertEqual(rewrite(command), "actx " + command)

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


class CargoRewriteUnitTests(unittest.TestCase):
    def test_cargo_pure_ro_rewritten(self):
        self.assertEqual(rewrite("cargo check"), "actx cargo check")
        self.assertEqual(rewrite("cargo test"), "actx cargo test")
        self.assertEqual(rewrite("cargo build"), "actx cargo build")
        self.assertEqual(rewrite("cargo tree"), "actx cargo tree")

    def test_cargo_fmt_check_rewritten(self):
        self.assertEqual(rewrite("cargo fmt --check"), "actx cargo fmt --check")
        self.assertEqual(rewrite("cargo fmt -- --check"), "actx cargo fmt -- --check")
        self.assertEqual(rewrite("cargo fmt --all -- --check"), "actx cargo fmt --all -- --check")

    def test_cargo_fmt_plain_and_emit_rejected(self):
        self.assertIsNone(rewrite("cargo fmt"))
        self.assertIsNone(rewrite("cargo fmt --all"))
        self.assertIsNone(rewrite("cargo fmt -- --emit files"))
        self.assertIsNone(rewrite("cargo fmt -- --emit=files"))

    def test_cargo_clippy_rewritten(self):
        self.assertEqual(rewrite("cargo clippy"), "actx cargo clippy")
        self.assertEqual(rewrite("cargo clippy --all-targets"), "actx cargo clippy --all-targets")
        self.assertEqual(rewrite("cargo clippy -- -D warnings"), "actx cargo clippy -- -D warnings")

    def test_cargo_clippy_fix_rejected(self):
        self.assertIsNone(rewrite("cargo clippy --fix"))
        self.assertIsNone(rewrite("cargo clippy --fix=allow-no-vcs"))
        self.assertIsNone(rewrite("cargo clippy --all-targets --fix"))

    def test_cargo_metadata_and_package(self):
        self.assertEqual(rewrite("cargo metadata --no-deps"), "actx cargo metadata --no-deps")
        self.assertIsNone(rewrite("cargo metadata"))
        self.assertEqual(rewrite("cargo package --list"), "actx cargo package --list")
        self.assertIsNone(rewrite("cargo package"))

    def test_cargo_global_options_and_toolchains(self):
        self.assertEqual(rewrite("cargo +nightly fmt --check"), "actx cargo +nightly fmt --check")
        self.assertEqual(rewrite("cargo -q check"), "actx cargo -q check")
        self.assertEqual(rewrite("cargo -v clippy"), "actx cargo -v clippy")
        self.assertEqual(rewrite("cargo --color always check"), "actx cargo --color always check")
        self.assertEqual(rewrite("cargo --color=always check"), "actx cargo --color=always check")
        self.assertEqual(rewrite("cargo --offline check"), "actx cargo --offline check")
        self.assertEqual(rewrite("cargo --locked test"), "actx cargo --locked test")

    def test_cargo_mutating_and_destructive_rejected(self):
        self.assertIsNone(rewrite("cargo fix"))
        self.assertIsNone(rewrite("cargo clean"))
        self.assertIsNone(rewrite("cargo publish"))
        self.assertIsNone(rewrite("cargo yank"))
        self.assertIsNone(rewrite("cargo owner"))
        self.assertIsNone(rewrite("cargo login"))
        self.assertIsNone(rewrite("cargo logout"))
        self.assertIsNone(rewrite("cargo add serde"))
        self.assertIsNone(rewrite("cargo rm serde"))
        self.assertIsNone(rewrite("cargo update"))
        self.assertIsNone(rewrite("cargo install ripgrep"))


class MobileRewriteTests(unittest.TestCase):
    """TK-42: flutter/dart/swift/swiftlint/swiftformat/xcodebuild/xcrun/pod/
    ./gradlew dispatch heads."""

    def test_flutter_ro_rewritten(self):
        self.assertEqual(rewrite("flutter doctor"), "actx flutter doctor")
        self.assertEqual(rewrite("flutter analyze"), "actx flutter analyze")
        self.assertEqual(rewrite("flutter analyze lib/"), "actx flutter analyze lib/")
        self.assertEqual(rewrite("flutter test"), "actx flutter test")
        self.assertEqual(
            rewrite("flutter test --plain-name counter"),
            "actx flutter test --plain-name counter",
        )
        self.assertEqual(
            rewrite("flutter pub outdated"), "actx flutter pub outdated"
        )
        self.assertEqual(
            rewrite("flutter pub deps --style=compact"),
            "actx flutter pub deps --style=compact",
        )

    def test_flutter_interactive_and_mutating_rejected(self):
        self.assertIsNone(rewrite("flutter run"))
        self.assertIsNone(rewrite("flutter attach"))
        self.assertIsNone(rewrite("flutter logs"))
        self.assertIsNone(rewrite("flutter emulators --launch pixel"))
        self.assertIsNone(rewrite("flutter doctor --android-licenses"))
        self.assertIsNone(rewrite("flutter channel"))
        self.assertIsNone(rewrite("flutter upgrade"))
        self.assertIsNone(rewrite("flutter downgrade"))
        self.assertIsNone(rewrite("flutter pub get"))
        self.assertIsNone(rewrite("flutter pub add http"))
        self.assertIsNone(rewrite("flutter clean"))
        self.assertIsNone(rewrite("flutter build apk"))
        self.assertIsNone(rewrite("flutter"))

    def test_dart_ro_rewritten(self):
        self.assertEqual(rewrite("dart analyze"), "actx dart analyze")
        self.assertEqual(rewrite("dart analyze test/"), "actx dart analyze test/")
        self.assertEqual(rewrite("dart test"), "actx dart test")
        self.assertEqual(rewrite("dart test --name parser"), "actx dart test --name parser")

    def test_dart_other_rejected(self):
        self.assertIsNone(rewrite("dart run bin/tool.dart"))
        self.assertIsNone(rewrite("dart pub get"))
        self.assertIsNone(rewrite("dart compile exe bin/x.dart"))
        self.assertIsNone(rewrite("dart"))

    def test_swift_build_test_rewritten(self):
        self.assertEqual(rewrite("swift build"), "actx swift build")
        self.assertEqual(rewrite("swift build --product App"), "actx swift build --product App")
        self.assertEqual(rewrite("swift test"), "actx swift test")
        self.assertEqual(rewrite("swift test --filter Foo"), "actx swift test --filter Foo")

    def test_swift_interactive_rejected(self):
        self.assertIsNone(rewrite("swift repl"))
        self.assertIsNone(rewrite("swift run App"))
        self.assertIsNone(rewrite("swift package resolve"))
        self.assertIsNone(rewrite("swift"))

    def test_swiftlint_lint_rewritten(self):
        self.assertEqual(rewrite("swiftlint lint"), "actx swiftlint lint")
        self.assertEqual(
            rewrite("swiftlint lint --strict"), "actx swiftlint lint --strict"
        )

    def test_swiftlint_mutating_rejected(self):
        self.assertIsNone(rewrite("swiftlint"))
        self.assertIsNone(rewrite("swiftlint autocorrect"))
        self.assertIsNone(rewrite("swiftlint lint --fix"))

    def test_swiftformat_lint_rewritten(self):
        self.assertEqual(rewrite("swiftformat --lint ."), "actx swiftformat --lint .")
        self.assertEqual(rewrite("swiftformat --dryrun"), "actx swiftformat --dryrun")
        self.assertEqual(
            rewrite("swiftformat Sources --dry-run"), "actx swiftformat Sources --dry-run"
        )

    def test_swiftformat_mutating_rejected(self):
        self.assertIsNone(rewrite("swiftformat"))
        self.assertIsNone(rewrite("swiftformat ."))
        self.assertIsNone(rewrite("swiftformat Sources Tests"))
        self.assertIsNone(rewrite("swiftformat --lint . --fix"))

    def test_xcodebuild_ro_and_build_rewritten(self):
        self.assertEqual(rewrite("xcodebuild -list"), "actx xcodebuild -list")
        self.assertEqual(
            rewrite("xcodebuild -project App.xcodeproj -list"),
            "actx xcodebuild -project App.xcodeproj -list",
        )
        self.assertEqual(rewrite("xcodebuild -showsdks"), "actx xcodebuild -showsdks")
        self.assertEqual(
            rewrite("xcodebuild -showBuildSettings"),
            "actx xcodebuild -showBuildSettings",
        )
        self.assertEqual(
            rewrite("xcodebuild -scheme App build"),
            "actx xcodebuild -scheme App build",
        )
        self.assertEqual(
            rewrite("xcodebuild -destination 'platform=iOS Simulator,name=iPhone 15' test"),
            "actx xcodebuild -destination 'platform=iOS Simulator,name=iPhone 15' test",
        )

    def test_xcodebuild_bare_and_interactive_rejected(self):
        self.assertIsNone(rewrite("xcodebuild"))
        self.assertIsNone(
            rewrite("xcodebuild -allowProvisioningUpdates -scheme App build")
        )
        self.assertIsNone(rewrite("xcodebuild clean"))

    def test_xcrun_simctl_list_rewritten(self):
        self.assertEqual(
            rewrite("xcrun simctl list"), "actx xcrun simctl list"
        )
        self.assertEqual(
            rewrite("xcrun simctl list devices"), "actx xcrun simctl list devices"
        )

    def test_xcrun_other_rejected(self):
        self.assertIsNone(rewrite("xcrun simctl boot udid"))
        self.assertIsNone(rewrite("xcrun simctl erase udid"))
        self.assertIsNone(rewrite("xcrun --find clang"))
        self.assertIsNone(rewrite("xcrun"))

    def test_pod_ro_rewritten(self):
        self.assertEqual(rewrite("pod outdated"), "actx pod outdated")
        self.assertEqual(rewrite("pod list"), "actx pod list")

    def test_pod_mutating_rejected(self):
        self.assertIsNone(rewrite("pod install"))
        self.assertIsNone(rewrite("pod deintegrate"))
        self.assertIsNone(rewrite("pod update"))

    def test_gradlew_rewritten(self):
        self.assertEqual(rewrite("./gradlew build"), "actx ./gradlew build")
        self.assertEqual(rewrite("./gradlew test"), "actx ./gradlew test")
        self.assertEqual(
            rewrite("./gradlew :app:assembleDebug --console=plain"),
            "actx ./gradlew :app:assembleDebug --console=plain",
        )

    def test_gradlew_ro_forms_rewritten(self):
        # TK-55 F5: bare invocation (default tasks), value flags with
        # separate/`=`/glued forms and boolean flags keep rewriting.
        for command in (
            "./gradlew",
            "./gradlew test --tests com.Foo",
            "./gradlew test --tests=com.Foo",
            "./gradlew check --parallel -q",
            "./gradlew -Dorg.gradle.jvmargs=-Xmx2g test",
            "./gradlew -Pkotlin.incremental=true build",
        ):
            with self.subTest(command=command):
                self.assertEqual(rewrite(command), "actx " + command)

    def test_gradlew_ask_and_unknown_rejected(self):
        # TK-55 F5: publish/clean-class and unknown task verbs defer;
        # multi-task requires ALL positionals RO; undeclared flags fail
        # closed.
        for command in (
            "./gradlew publish",
            "./gradlew :app:publish",
            "./gradlew test publish",
            "./gradlew clean",
            "./gradlew unknownVerb",
            "./gradlew --write-locks dependencies",
            "./gradlew --stop",
        ):
            with self.subTest(command=command):
                self.assertIsNone(rewrite(command))

    def test_other_gradle_invocations_not_affected(self):
        # Absolute/`gradle` paths are different argv heads - untouched.
        self.assertIsNone(rewrite("gradle build"))
        self.assertIsNone(rewrite("./gradlew --stop; ls"))


# ----------------------------------------------------------------------
# TK-57 STEP-03 (REQ-04): endpoint/credential/project flag class per CLI
# family, incl. pflag_short clusters. Family flag matrix (head, denied
# member, semantics, spellings checked, source, verdict) - every head of
# cli_families.FAMILIES must have a row (test_family_matrix_covers_every_
# family below); a head added to FAMILIES without a matching row here
# fails that test on purpose.
# ----------------------------------------------------------------------

FAMILY_FLAG_MATRIX = {
    "docker": {
        "source": "docker --help (local, 2026-09-26, docker 29.1.5)",
        "members": (
            ("-H/--host", "daemon socket endpoint switch",
             ("-H tcp://e", "--host tcp://e", "--host=tcp://e")),
            ("-c/--context", "daemon context (endpoint) switch",
             ("-c ctx", "--context ctx", "--context=ctx",
              "-Ac ctx (clustered after boolean -A... n/a; -ac ctx)")),
            ("--config", "alternate client config dir (incl. contexts)",
             ("--config /tmp/x",)),
            ("--tlscacert", "alternate TLS CA (trust root) file",
             ("--tlscacert=/tmp/x",)),
            ("--tlscert", "alternate TLS client cert", ("--tlscert=/tmp/x",)),
            ("--tlskey", "alternate TLS client key", ("--tlskey=/tmp/x",)),
        ),
    },
    "kubectl": {
        "source": "kubectl options; kubectl get/describe/top/events/logs "
                   "--help (local, 2026-09-26, kubectl v1.x)",
        "members": (
            ("-s/--server", "API server endpoint switch",
             ("-s https://e", "-s=https://e", "--server https://e",
              "-As https://e (clustered behind boolean -A)")),
            ("--token", "bearer credential handover", ("--token=x",)),
            ("--user", "kubeconfig user (credential) switch",
             ("--user=admin",)),
            ("--username", "basic-auth credential handover",
             ("--username=x",)),
            ("--password", "basic-auth credential handover",
             ("--password=x",)),
            ("--as/--as-group/--as-uid", "impersonation", ("--as=admin",)),
            ("--client-certificate/--client-key", "TLS identity swap",
             ("--client-certificate=/tmp/x",)),
            ("--certificate-authority", "TLS trust root swap",
             ("--certificate-authority=/tmp/x",)),
            ("--insecure-skip-tls-verify", "disables cert validation", ()),
            ("--tls-server-name", "redirects cert validation target", ()),
        ),
    },
    "helm": {
        "source": "helm.sh/docs/helm/helm/ (fetched 2026-09-26; helm not "
                   "installed locally)",
        "members": (
            ("--kube-apiserver", "API server endpoint switch", ()),
            ("--kube-token", "bearer credential handover", ()),
            ("--kube-as-user/--kube-as-group", "impersonation", ()),
            ("--kube-ca-file", "TLS trust root swap", ()),
            ("--kube-tls-server-name", "redirects cert validation target", ()),
            ("--kube-insecure-skip-tls-verify", "disables cert validation", ()),
            ("--kube-context", "kubeconfig context switch", ()),
            ("--kubeconfig", "alternate kubeconfig file", ()),
            ("--registry-config", "alternate registry credential file", ()),
            ("--repository-config", "alternate repo config file", ()),
        ),
    },
    "gh": {
        "source": "gh <ns> --help (local, 2026-09-26, gh 2.100.0)",
        "members": (
            ("--hostname", "GitHub host switch",
             ("--hostname=evil.com",)),
        ),
        "note": "no short form; not accepted by any declared RO-verb "
                "subcommand in gh 2.100.0 (verified live: errors 'unknown "
                "flag') - kept per plan as defensive/inert, flagged "
                "unconfirmed-live in the stream report. -R/--repo stays "
                "OUT (REQ-11 NON-GOAL).",
    },
    "gcloud": {
        "source": "docs.cloud.google.com/sdk/gcloud/reference (fetched "
                   "2026-09-26; gcloud not installed locally)",
        "members": (
            ("--impersonate-service-account", "impersonation", ()),
            ("--account", "identity switch", ()),
            ("--access-token-file", "credential handover", ()),
            ("--configuration", "named config bundle switch", ()),
            ("--credential-file-override", "credential handover", ()),
            ("--flags-file", "flag injection from file", ()),
            ("--project", "project switch", ()),
            ("--billing-project", "billing project switch", ()),
        ),
    },
    "bq": {
        "source": "plan v4 S7 STEP-03 (absl flags; bq not installed "
                   "locally) - --location excluded (region, not project)",
        "members": (
            ("credential_file", "credential handover", ("-credential_file=x",)),
            ("service_account", "identity switch", ()),
            ("service_account_credential_file", "credential handover", ()),
            ("service_account_private_key_file", "credential handover", ()),
            ("api", "API endpoint switch", ()),
            ("use_gce_service_account", "identity switch", ()),
            ("application_default_credential_file", "credential handover", ()),
            ("oauth_access_token", "credential handover", ()),
            ("project_id", "project switch", ("--project_id=p",)),
            ("dataset_id", "dataset scope switch", ()),
        ),
    },
    "vercel": {
        "source": "plan v4 S7 STEP-03 (vercel docs; not installed locally)",
        "members": (
            ("-t/--token", "credential handover", ("--token x",)),
            ("-S/--scope", "account scope switch", ("--scope t",)),
            ("-Q/--global-config", "alternate global config dir", ()),
            ("-A/--local-config", "alternate local config file", ()),
            ("--team", "team context switch", ()),
            ("--api", "API endpoint switch", ()),
        ),
    },
    "netlify": {
        "source": "plan v4 S7 STEP-03 (netlify docs; not installed locally)",
        "members": (
            ("--auth", "credential handover", ()),
            ("--site", "site (project) switch", ()),
        ),
    },
    "flyctl": {
        "source": "plan v4 S7 STEP-03 (fly.io docs; not installed locally)",
        "members": (
            ("-t/--access-token", "credential handover",
             ("--access-token x",)),
            ("-a/--app", "target app switch", ()),
            ("--org", "organization switch", ()),
        ),
    },
    "supabase": {
        "source": "supabase.com/docs/reference/cli/introduction "
                   "(fetched 2026-09-26; not installed locally)",
        "members": (
            ("--project-ref", "project switch", ()),
            ("--profile", "auth profile switch (doc-confirmed sibling, "
                          "not in the plan's original list)", ()),
        ),
        "note": "--token/--access-token checked and NOT found (auth is "
                "via the SUPABASE_ACCESS_TOKEN env var) - excluded.",
    },
    "railway": {
        "source": "plan v4 S7 STEP-03 (railway docs; not installed locally)",
        "members": (
            ("--project", "project switch", ()),
            ("--environment", "environment switch", ()),
            ("--service", "service switch", ()),
        ),
    },
    "wrangler": {
        "source": "developers.cloudflare.com/workers/wrangler/commands/"
                   "general/ (fetched 2026-09-26; not installed locally)",
        "members": (
            ("--config/-c", "alternate wrangler config file", ()),
            ("--env/-e", "environment switch", ()),
            ("--profile", "auth profile switch (doc-confirmed sibling, "
                          "not in the plan's original list)", ()),
        ),
        "note": "--account-id checked and NOT found as a global flag "
                "(only --account on `whoami`) - excluded.",
    },
    "terraform": {
        "source": "developer.hashicorp.com/terraform/cli/commands "
                   "(fetched 2026-09-26)",
        "members": (
            ("-chdir", "switches the working dir (config/backend/creds)", ()),
        ),
        "note": "-state checked and NOT a current global flag - excluded; "
                "-var-file only supplies variable values, not an "
                "endpoint/account switch - excluded (plan's own '?' "
                "markers).",
    },
    "redis-cli": {
        "source": "REQ-11 NON-GOAL (TK-40/TK-43 value_flags decision)",
        "members": (),
        "note": "checked, no REQ-04 members beyond the already-excluded "
                "-h/-p/-a (host/port/password - declared value_flags, "
                "out of contract by REQ-11).",
    },
}


class FamilyFlagMatrixTests(unittest.TestCase):
    def test_family_matrix_covers_every_family(self):
        # A head added to cli_families.FAMILIES without a matching matrix
        # row (members or an explicit "checked, no members" note) fails
        # this test - the TK-57 REQ-04 test-invariant (plan S7 STEP-03).
        import actx_lib.cli_families as cli_families

        missing = sorted(
            set(cli_families.FAMILIES) - set(FAMILY_FLAG_MATRIX)
        )
        self.assertEqual(missing, [], "families missing a matrix row")
        for head, row in FAMILY_FLAG_MATRIX.items():
            self.assertTrue(row["source"], head)
            self.assertTrue(row["members"] or "note" in row, head)


class DeniedEndpointFlagTests(unittest.TestCase):
    def test_docker_endpoint_flags_rejected(self):
        for command in (
            "docker ps -H tcp://e:2375",
            "docker -H tcp://e ps",
            "docker ps --host=tcp://e",
            "docker ps -c prod",
            "docker -c prod ps",
            "docker ps --context=prod",
            "docker ps --config /tmp/x",
            "docker ps --tlscacert=/tmp/ca.pem",
            "docker ps --tlscert=/tmp/c.pem",
            "docker ps --tlskey=/tmp/k.pem",
        ):
            with self.subTest(command=command):
                self.assertIsNone(rewrite(command))

    def test_docker_ro_forms_still_rewrite(self):
        for command in (
            "docker ps",
            "docker logs c",
            "docker ps -a",
            "docker images -a",
            "docker ps -n 5 web",
            "docker system df -v",
        ):
            with self.subTest(command=command):
                self.assertEqual(rewrite(command), "actx " + command)

    def test_kubectl_endpoint_flags_rejected(self):
        for command in (
            "kubectl get pods --as=admin",
            "kubectl get pods -As https://evil:6443",
            "kubectl get pods -s=https://e",
            "kubectl get pods --server https://e",
            "kubectl get pods --user=admin",
            "kubectl get pods --token=x",
            "kubectl get pods --username=x",
            "kubectl get pods --password=x",
            "kubectl get pods --client-certificate=/tmp/x",
            "kubectl get pods --client-key=/tmp/x",
            "kubectl get pods --certificate-authority=/tmp/x",
            "kubectl get pods --insecure-skip-tls-verify=true",
            "kubectl get pods --tls-server-name=evil",
        ):
            with self.subTest(command=command):
                self.assertIsNone(rewrite(command))

    def test_kubectl_ro_forms_still_rewrite(self):
        for command in (
            "kubectl get pods -n prod --context x",
            "kubectl get pods -o wide",
            "kubectl get pods -ojson",
            "kubectl get pods -A",
            "kubectl get pods -w",
            "kubectl logs -f pod/web-abc",
        ):
            with self.subTest(command=command):
                self.assertEqual(rewrite(command), "actx " + command)

    def test_helm_endpoint_flags_rejected(self):
        for command in (
            "helm list --kube-token x",
            "helm list --kube-context prod",
            "helm list --kube-apiserver https://e",
            "helm list --kubeconfig /tmp/x",
            "helm list --registry-config /tmp/x",
            "helm list --repository-config /tmp/x",
        ):
            with self.subTest(command=command):
                self.assertIsNone(rewrite(command))

    def test_helm_ro_forms_still_rewrite(self):
        self.assertEqual(rewrite("helm list"), "actx helm list")
        self.assertEqual(
            rewrite("helm template mychart"), "actx helm template mychart"
        )

    def test_gcloud_endpoint_flags_rejected(self):
        for command in (
            "gcloud projects list --impersonate-service-account=a@b",
            "gcloud projects list --project p",
            "gcloud projects list --flags-file f.yaml",
            "gcloud projects list --account=a@b",
            "gcloud projects list --billing-project=p",
            "gcloud projects list --access-token-file=/tmp/x",
            "gcloud projects list --configuration=other",
            "gcloud projects list --credential-file-override=/tmp/x",
        ):
            with self.subTest(command=command):
                self.assertIsNone(rewrite(command))

    def test_bq_endpoint_flags_rejected(self):
        for command in (
            "bq ls --project_id=p",
            "bq ls -credential_file=x",
            "bq ls --service_account=a@b",
            "bq ls --api=https://evil",
            "bq ls --oauth_access_token=x",
        ):
            with self.subTest(command=command):
                self.assertIsNone(rewrite(command))

    def test_bq_ro_forms_still_rewrite(self):
        self.assertEqual(rewrite("bq ls"), "actx bq ls")

    def test_vercel_endpoint_flags_rejected(self):
        for command in (
            "vercel whoami --token x",
            "vercel list --scope t",
            "vercel list -S t",
            "vercel whoami -t x",
        ):
            with self.subTest(command=command):
                self.assertIsNone(rewrite(command))

    def test_flyctl_endpoint_flags_rejected(self):
        self.assertIsNone(rewrite("flyctl status --access-token x"))

    def test_gh_endpoint_flags_rejected(self):
        self.assertIsNone(rewrite("gh pr list --hostname e.com"))

    def test_gh_repo_selector_still_rewrites(self):
        # REQ-11 NON-GOAL: -R/--repo stays out of this class.
        for command in (
            "gh pr list",
            "gh pr -R o/r list",
            "gh issue --repo o/r list",
            "gh --repo=o/r pr list",
        ):
            with self.subTest(command=command):
                self.assertEqual(rewrite(command), "actx " + command)


# ----------------------------------------------------------------------
# TK-57 STEP-04 (REQ-05): `next` closed RO-subcommand allow-list.
# ----------------------------------------------------------------------

class NextClosedSubcommandTests(unittest.TestCase):
    def test_ro_subcommands_rewritten(self):
        for command in ("next lint", "next build", "next info"):
            with self.subTest(command=command):
                self.assertEqual(rewrite(command), "actx " + command)

    def test_other_forms_rejected(self):
        for command in (
            "next",
            "next dev",
            "next start -p 3000",
            "next telemetry disable",
            "next lint --fix",
        ):
            with self.subTest(command=command):
                self.assertIsNone(rewrite(command))


# ----------------------------------------------------------------------
# TK-57 STEP-04b: `_find_ok` -fprint0 and siblings (class "writes a file").
# ----------------------------------------------------------------------

class FindWriteActionTests(unittest.TestCase):
    def test_fprint_family_rejected(self):
        for command in (
            "find . -fprint0 /tmp/out",
            "find . -fprint /tmp/out",
            "find . -fprintf /tmp/out %p",
            "find . -fls /tmp/out",
        ):
            with self.subTest(command=command):
                self.assertIsNone(rewrite(command))

    def test_plain_find_still_rewrites(self):
        self.assertEqual(
            rewrite("find . -name '*.py'"), "actx find . -name '*.py'"
        )


# ----------------------------------------------------------------------
# TK-57 STEP-06 rewriter part (REQ-08): git argv exec-flags on the
# rewritten mutators.
# ----------------------------------------------------------------------

class GitExecFlagTests(unittest.TestCase):
    def test_exec_flags_rejected(self):
        for command in (
            "git fetch --upload-pack='touch x' .",
            "git pull --upload-pack=x",
            "git push --receive-pack=x origin",
            "git push --exec=x origin",
            "git fetch --upl=x .",       # unambiguous abbreviation
            "git push --rece=x origin",  # unambiguous abbreviation
            "git push --ex=x origin",    # unambiguous abbreviation
        ):
            with self.subTest(command=command):
                self.assertIsNone(rewrite(command))

    def test_ro_and_unrelated_forms_still_rewrite(self):
        for command in (
            "git fetch",
            "git pull --rebase",
            "git push origin main",
            "git push --recurse-submodules=check",
        ):
            with self.subTest(command=command):
                self.assertEqual(rewrite(command), "actx " + command)


if __name__ == "__main__":
    unittest.main()
