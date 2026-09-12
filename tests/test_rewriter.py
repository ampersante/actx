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
            "go test -run X ./...",
            "tsc --noEmit",
            "pytest -q",
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


if __name__ == "__main__":
    unittest.main()
