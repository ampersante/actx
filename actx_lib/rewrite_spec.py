"""TK-60 (REQ-04): closed per-head admission specs for the rewriter.

Pure data (+ the tiny constructor below); zero side effects at import time
beyond deriving family-driven entries from `cli_families.FAMILIES`. The
engine (`actx_lib/rewriter.py`) is the only reader/interpreter of this
table - this module never decides anything by itself.

Grammar (plan `2026-09-27-gate-split-allowlist.md` S5.1) - one record per
head or per verb-path node:

  verbs         -- None (no subcommands at this level) or {literal token:
                   child level}. A verb is consumed by exact token equality;
                   only the FIRST non-flag token is tried against it (a verb
                   never appears twice).
  bool          -- exact boolean flag spellings (no abbreviations, ever).
  value         -- {flag: "any" | "int" | frozenset(allowed values)}.
                   REQUIRED-value flags: `--f=v` / `--f v` / `-fv` / `-f v`.
                   A following separate token starting with "-" is NEVER
                   accepted as the value (closes the "value looks like the
                   next flag" ambiguity) - engine enforces this, not data.
  optional      -- same value-domain as `value`, but OPTIONAL: only the
                   glued/`=` form is ever consumed; a following bare token
                   is left alone (never treated as this flag's value).
  numeric       -- True admits a bare short numeric flag (`-5`, `-50`) at
                   this level (git log -5, head -20).
  cluster       -- True admits a cluster of this level's OWN boolean short
                   flags (`-la`); a cluster containing an unknown char or a
                   value-flag char rejects (fail closed).
  positional    -- "any" | "none" | ("max", N).
  after_dashdash -- "forbid" | "positional" | ("forward", <FORWARD_SPECS key>).
                   `dashdash_literals` (default `("--",)`) names the token(s)
                   that trigger this at THIS level only (go's test binary
                   boundary is the literal `-args`/`--args`, not `--`).
  hook          -- name of a named semantic check (REQ-06) applied by the
                   engine in addition to (never instead of) the flag/verb
                   grammar above; None for none. Hooks never duplicate the
                   grammar itself - they exist only where the grammar's
                   flag/positional primitives cannot express the decision
                   (SQL payload classification, gradle task classification).
  inherit       -- whether the PARENT level's own bool/value/optional stay
                   admitted for the tokens that follow THIS level's verb
                   (pflag/Cobra families: True; git: False). Declared
                   explicitly on every non-root level that has a parent.
  require_verb  -- True: a bare invocation (no verb token at all) does not
                   match this level (git stash bare must not rewrite).
  require_any_of -- at least one of these literal tokens must appear
                   somewhere in the tail (cargo fmt/metadata/package each
                   require exactly one specific flag; swiftformat/
                   xcodebuild require one of several).
  forbid_write_token -- old's shared `_has_write_token` predicate (ruff/
                   eslint/swiftlint/swiftformat): reject if the tail
                   carries the literal "--fix"/"fix"/"format" or any token
                   starting with "--fix".

Source per head, in order of preference: (1) exact rewrite corpus token
usage; (2) tables already vetted with a dated citation elsewhere in this
codebase (`cli_families.FAMILIES`, `cli_families.GRADLE_*`); (3) live
`--help`/`-h`/man pulls done for this task or a follow-up research pass
(git, gh, grep, docker, kubectl, cargo, uv, pip, sqlite3, flutter/dart,
swift/xcrun - each section below says which); (4) official docs (DOC) for
CLIs not installed; (5) well-established stable-CLI knowledge (TRAIN),
flagged low-confidence inline. A head absent from HEAD_SPECS has NO
confirmed source and does not rewrite at all (TK-60 stop rule).

Owner decisions on the behaviour-parity items this pass's research
flagged (each called out at its own definition below): `dbt`'s `run`/
`build` verbs are REMOVED (warehouse-mutating, data-integrity criterion -
`test`/`compile`/`list`/`ls` stay); `xcodebuild`'s `require_any_of` keeps
`-scheme`/`-destination` as today (a real gating gap flagged by research,
left unfixed by owner decision, not silently); `git commit --amend` stays
excluded; `tsc` keeps no `require_any_of` no-emit gate; `next build`'s
spec is unchanged (bare, no flags) - all four decided AS TODAY.
"""

from actx_lib import cli_families

# Owned here (single source); rewriter.py re-exports it under the same name
# so `filters/git_filter.py`'s existing `from actx_lib.rewriter import
# BRANCH_READ_ONLY` keeps working unchanged.
BRANCH_READ_ONLY = frozenset({
    "-a", "-r", "-l", "--list", "--show-current",
    "-v", "--verbose", "-vv", "--no-color",
    # git branch -h, 2026-09-27:
    "-q", "--quiet", "-i", "--ignore-case", "--omit-empty",
})


def spec(verbs=None, bool=(), value=None, optional=None, numeric=False,
         cluster=False, positional="none", after_dashdash="forbid",
         hook=None, inherit=False, require_verb=False,
         dashdash_literals=("--",), require_any_of=(), forbid_write_token=False):
    return {
        "verbs": verbs,
        "bool": frozenset(bool),
        "value": dict(value or {}),
        "optional": dict(optional or {}),
        "numeric": numeric,
        "cluster": cluster,
        "positional": positional,
        "after_dashdash": after_dashdash,
        "hook": hook,
        "inherit": inherit,
        "require_verb": require_verb,
        "dashdash_literals": tuple(dashdash_literals),
        "require_any_of": frozenset(require_any_of),
        "forbid_write_token": forbid_write_token,
    }


# ---------------------------------------------------------------------
# Independent grammars matched after a `--`/boundary hand-off
# (cargo's forwarded libtest/rustfmt/clippy-lint args, go test's forwarded
# test-binary args - REQ-07/after_dashdash "forward"). Each is itself a
# full `spec()`, matched against the tokens that follow the boundary
# exactly like a head grammar would be.
# ---------------------------------------------------------------------
FORWARD_SPECS = {
    # rustfmt --help (LIVE, 2026-09-27, rustfmt installed): `--emit
    # [files|stdout]` - "files" (the default) WRITES formatted output back
    # to the source files (rustfmt's own docs: "What data to emit and
    # how"); only "stdout" is read-only. Finding B (wave 2026-09-27,
    # confirmed live): the previous domain wrongly admitted "files"/"file",
    # so `cargo fmt --check -- --emit files` was rewritten despite
    # mutating source - the OLD (pre-TK-60) rewriter correctly rejected
    # both spellings by name; this restores that behaviour via the closed
    # domain instead of a literal-spelling denylist. `--edition
    # [2015|2018|2021|2024]` is a genuine read-only rustfmt flag (which
    # edition's syntax to parse), added per the same `--help` output.
    "cargo_fmt_forward": spec(
        bool=("--check",),
        value={"--emit": frozenset({"stdout"}),
               "--edition": frozenset({"2015", "2018", "2021", "2024"})},
        positional="none",
    ),
    # `cargo clippy -- <rustc lint flags>` (corpus positive: `cargo clippy
    # -- -D warnings`) - rustc's lint-level flags only.
    "cargo_clippy_forward": spec(
        value={"-D": "any", "-W": "any", "-A": "any", "-F": "any",
               "--deny": "any", "--warn": "any", "--allow": "any",
               "--forbid": "any"},
        positional="none",
    ),
    # `cargo test -- <libtest args>` (LIVE compiled-binary `-- --help`,
    # 2026-09-27, this session, plus a follow-up direct run confirming
    # both spellings actually execute on the installed toolchain):
    # "--no-capture" is the documented spelling (shown by `-- --help`);
    # "--nocapture" is an undocumented-but-accepted alias (older libtest
    # convention) - both admitted since both were independently verified
    # to run, not just appear in --help output.
    "cargo_test_libtest_forward": spec(
        bool=("--include-ignored", "--ignored", "--force-run-in-process",
              "--exclude-should-panic", "--test", "--bench", "--list",
              "--fail-fast", "--no-capture", "--nocapture",
              "-q", "--quiet", "--exact",
              "--show-output", "--report-time", "--ensure-time", "--shuffle"),
        value={"--test-threads": "int", "--skip": "any",
               "--color": frozenset({"auto", "always", "never"}),
               "--format": frozenset({"pretty", "terse", "json", "junit"}),
               "--shuffle-seed": "int"},
        optional={"-Z": "any"},
        positional="any",  # bare FILTER strings (test-name substrings)
    ),
    # go test's compiled test-binary flags, forwarded after `-args`/
    # `--args` (DOC pkg.go.dev/cmd/go#hdr-Testing_flags; go not installed
    # locally this session, not independently re-verified live - recommend
    # an owner spot-check). Deliberately does NOT include -test.coverprofile
    # /-test.cpuprofile/etc (write-to-user-path class) or a bare "-o" (not
    # a real -test.* flag) - `go test ./... -args -test.coverprofile=x`
    # stays rejected (plan STEP-W5 explicit pin), while legitimate forwarded
    # flags (-test.run/-test.v/...) are recovered.
    "go_test_binary_forward": spec(
        bool=("-test.v", "--test.v", "-test.short", "--test.short",
              "-test.failfast", "--test.failfast", "-test.paniconexit0",
              "--test.paniconexit0", "-test.fullpath", "--test.fullpath",
              "-test.benchmem", "--test.benchmem"),
        value={"-test.run": "any", "--test.run": "any",
               "-test.skip": "any", "--test.skip": "any",
               "-test.count": "int", "--test.count": "int",
               "-test.parallel": "int", "--test.parallel": "int",
               "-test.timeout": "any", "--test.timeout": "any",
               "-test.cpu": "any", "--test.cpu": "any",
               "-test.list": "any", "--test.list": "any",
               "-test.shuffle": "any", "--test.shuffle": "any",
               "-test.bench": "any", "--test.bench": "any",
               "-test.benchtime": "any", "--test.benchtime": "any"},
        positional="none",
    ),
}


# ---------------------------------------------------------------------
# git (installed locally; `git status/log/diff/show/blame/rev-parse/add/
# commit/push/pull/fetch/branch/stash -h` + `man git-rev-parse` re-checked
# 2026-09-27, git 2.55.0). No global flags admitted before the subcommand
# (today's dispatch requires tokens[1] to literally be the verb).
#
# Mutators (add/commit/push/pull/fetch) are read at PARITY with today's
# rewriter, which admits their full documented surface minus a narrow
# denylist - not the strict "independently proven safe" bar used for
# read-only verbs (that bar would be a NEW narrowing, not a preserved
# one). Interactive-editor flags (-p/--patch, -i/--interactive, -e/--edit,
# -c/--reedit-message, --fixup) and exec-by-name flags (--upload-pack,
# --receive-pack, --exec, -s/--strategy for pull) are excluded by omission
# as the same class of hole TK-55/57 already closed elsewhere.
#
# `--amend`/`--no-amend` on `commit` is a NAMED OWNER-DECISION, left
# EXCLUDED here (not resolved either way by this pass): old admitted it
# unconditionally (parity argument), but it rewrites history that may
# already be shared, a qualitatively different risk than an ordinary new
# commit. Uncomment the two literals in `commit`'s `bool` to admit it.
# ---------------------------------------------------------------------
_GIT_LOG_DIFF_SHOW_BOOL = (
    "--oneline", "--graph", "--all", "--decorate", "--no-decorate",
    "--stat", "--name-only", "--name-status", "-p", "--patch",
    "--no-merges", "--merges", "--first-parent", "--cached", "--staged",
    "--no-color",
    "-q", "--quiet", "--no-quiet",
    "--source", "--no-source",
    "--use-mailmap", "--no-use-mailmap", "--mailmap", "--no-mailmap",
    "--clear-decorations",
    "--no-decorate-refs", "--no-decorate-refs-exclude",
    # -s/--no-patch (suppress diff output, show only the commit message) -
    # applies to log AND show alike (`git show -s <rev>`).
    "-s", "--no-patch",
)
_GIT_LOG_DIFF_SHOW_VALUE = {
    "--author": "any", "--since": "any", "--until": "any",
    "--grep": "any", "--format": "any", "--pretty": "any",
    "--max-count": "int", "-n": "int",
    "--decorate-refs": "any", "--decorate-refs-exclude": "any",
    "-L": "any",
    # -S (pickaxe: commits whose diff adds/removes <string>) and --date
    # (commit-date display format) - real git log/show flags, history-
    # replay pins: `git log --oneline -S <str>`, `git log -n <N>
    # --format=<v> --date=<v>`.
    "-S": "any", "--date": "any",
}
_GIT_LOG_DIFF_SHOW_OPTIONAL = {"--decorate": "any"}

# `git diff` does NOT share log/show's revision-walk/decoration flags
# (--oneline/--graph/--all/--decorate*/--first-parent/--merges/--source*/
# --mailmap*/--clear-decorations/--author/--since/--until/--grep/-n/
# --max-count/-L/--follow/--pretty/--format all belong to commands that
# WALK a revision range or display commits - diff only ever compares two
# trees/commits, it has no such flags) - built as an entirely self-
# contained set, not derived from the shared log/show tuple above.
_GIT_DIFF_BOOL = (
    "--check", "--numstat",
    "-p", "--patch", "-s", "--no-patch", "-u", "-W", "--no-function-context",
    "--raw", "--patch-with-raw", "--patch-with-stat", "--shortstat",
    "--cumulative", "--summary", "--name-only", "--name-status", "--stat",
    "--compact-summary", "--no-compact-summary", "--binary",
    "--full-index", "--no-full-index", "-z", "--no-prefix", "--default-prefix",
    "-D", "--irreversible-delete",
    "--find-copies-harder", "--no-find-copies-harder", "--no-renames",
    "--rename-empty", "--no-rename-empty",
    "--minimal", "-w", "--ignore-all-space", "-b", "--ignore-space-change",
    "--ignore-space-at-eol", "--ignore-cr-at-eol", "--ignore-blank-lines",
    "--indent-heuristic", "--no-indent-heuristic", "--patience", "--histogram",
    "-a", "--text", "--no-text", "-R", "--exit-code", "--no-exit-code",
    "--quiet", "--ita-invisible-in-index", "--ita-visible-in-index",
    "--pickaxe-all", "--pickaxe-regex", "--no-color",
    "--no-ignore-matching-lines",
    "--cached", "--staged",
    # `--no-index` compares two paths outside any repository - RO,
    # history-replay pin: `git diff --no-index --unified=<n> -- <paths>`.
    "--no-index",
    # EXCLUDED (never listed): --ext-diff/--no-ext-diff (execs configured
    # external diff program), --textconv/--no-textconv (execs configured
    # textconv filter), --output <file> (writes a user-named file);
    # --follow (log-only: follows renames while WALKING history, diff
    # doesn't walk).
)
_GIT_DIFF_VALUE = {
    "-U": "int", "--unified": "int",
    "--stat-width": "int", "--stat-name-width": "int",
    "--stat-graph-width": "int", "--stat-count": "int",
    "--ws-error-highlight": "any",
    "--src-prefix": "any", "--dst-prefix": "any", "--line-prefix": "any",
    "--inter-hunk-context": "int",
    "--output-indicator-new": "any", "--output-indicator-old": "any",
    "--output-indicator-context": "any",
    "-l": "int",
    "--diff-algorithm": frozenset({"myers", "minimal", "patience", "histogram"}),
    "--anchored": "any", "--word-diff-regex": "any", "--color-moved-ws": "any",
    "-S": "any", "-G": "any",
    "-O": "any", "--rotate-to": "any", "--skip-to": "any",
    "--find-object": "any", "--diff-filter": "any", "--max-depth": "int",
    "-I": "any", "--ignore-matching-lines": "any",
}
_GIT_DIFF_OPTIONAL = {
    "-U": "int", "--unified": "int",
    "-X": "any", "--dirstat": "any", "--dirstat-by-file": "any",
    "--stat": "any", "--color": "any",
    "-B": "any", "--break-rewrites": "any",
    "-M": "int", "--find-renames": "int",
    "-C": "int", "--find-copies": "int",
    "--abbrev": "int", "--relative": "any",
    "--word-diff": frozenset({"color", "plain", "porcelain", "none"}),
    "--color-words": "any", "--color-moved": "any",
    "--ignore-submodules": frozenset({"none", "untracked", "dirty", "all"}),
    "--submodule": "any",
}

HEAD_SPECS = {
    "git": spec(verbs={
        "status": spec(
            bool=("-v", "--verbose", "--no-verbose", "-s", "--short", "--no-short",
                  "-b", "--branch", "--no-branch", "--show-stash", "--no-show-stash",
                  "--ahead-behind", "--no-ahead-behind", "--long", "--no-long",
                  "-z", "--null", "--no-null", "--renames", "--no-renames"),
            # NOTE: real git syntax is `--porcelain[=<version>]` with a
            # plain version NUMBER ("1"/"2"); domain widened to "any" (not
            # "int") because a history-replay pin shows `--porcelain=v2`
            # actually being run/rewritten in practice (old's fully-open
            # status dispatch never validated the value either way) -
            # `--porcelain` only ever selects an output FORMAT, so a wider
            # domain carries no write/exec risk regardless of spelling.
            optional={"--porcelain": "any",
                      "-u": frozenset({"all", "normal", "no"}),
                      "--untracked-files": frozenset({"all", "normal", "no"}),
                      "--ignored": frozenset({"traditional", "matching", "no"}),
                      "--ignore-submodules": frozenset({"all", "dirty", "untracked"}),
                      "--column": "any", "-M": "int", "--find-renames": "int"},
            cluster=True, positional="any", after_dashdash="positional"),
        "log": spec(bool=_GIT_LOG_DIFF_SHOW_BOOL, value=_GIT_LOG_DIFF_SHOW_VALUE,
                    optional=_GIT_LOG_DIFF_SHOW_OPTIONAL, numeric=True,
                    positional="any", after_dashdash="positional"),
        "diff": spec(bool=_GIT_DIFF_BOOL, value=_GIT_DIFF_VALUE,
                     optional=_GIT_DIFF_OPTIONAL,
                     positional="any", after_dashdash="positional"),
        "show": spec(bool=_GIT_LOG_DIFF_SHOW_BOOL, value=_GIT_LOG_DIFF_SHOW_VALUE,
                     optional=_GIT_LOG_DIFF_SHOW_OPTIONAL,
                     positional="any", after_dashdash="positional"),
        "blame": spec(
            bool=("--incremental", "--no-incremental", "-b", "--root", "--no-root",
                  "--show-stats", "--no-show-stats", "--progress", "--no-progress",
                  "--score-debug", "-f", "--show-name", "--no-show-name",
                  "-n", "--show-number", "--no-show-number", "-p", "--porcelain",
                  "--no-porcelain", "--line-porcelain", "-c", "-t", "-l", "-s",
                  "-e", "--show-email", "--no-show-email", "-w",
                  "--color-lines", "--color-by-age"),
            value={"--diff-algorithm": frozenset({"myers", "minimal", "patience", "histogram"}),
                   "--ignore-rev": "any", "--no-ignore-rev": "any",
                   "--ignore-revs-file": "any", "--no-ignore-revs-file": "any",
                   "-S": "any", "--contents": "any", "--no-contents": "any",
                   "-L": "any"},
            optional={"-C": "int", "-M": "int", "--abbrev": "int"},
            positional="any", after_dashdash="positional"),
        "rev-parse": spec(
            bool=("--short", "--verify", "--is-inside-work-tree",
                  "--show-toplevel", "--abbrev-ref", "-q", "--quiet", "--sq",
                  "--not", "--symbolic", "--symbolic-full-name",
                  "--revs-only", "--no-revs", "--flags", "--no-flags",
                  "--all", "--git-dir", "--git-common-dir",
                  "--show-superproject-working-tree", "--shared-index-path",
                  "--absolute-git-dir", "--is-inside-git-dir",
                  "--is-bare-repository", "--is-shallow-repository",
                  "--show-cdup", "--show-prefix", "--show-ref-format",
                  "--local-env-vars", "--keep-dashdash", "--stop-at-non-option",
                  "--stuck-long", "--parseopt", "--sq-quote"),
            value={"--default": "any", "--prefix": "any", "--glob": "any",
                   "--exclude": "any", "--exclude-hidden": frozenset({"fetch", "receive", "uploadpack"}),
                   "--disambiguate": "any", "--resolve-git-dir": "any",
                   "--git-path": "any", "--since": "any", "--after": "any",
                   "--until": "any", "--before": "any",
                   "--output-object-format": frozenset({"sha1", "sha256", "storage"}),
                   "--path-format": frozenset({"absolute", "relative"})},
            optional={"--short": "int", "--abbrev-ref": frozenset({"strict", "loose"}),
                      "--branches": "any", "--tags": "any", "--remotes": "any",
                      "--show-object-format": frozenset({"storage", "input", "output", "compat"})},
            positional="any"),
        "add": spec(
            bool=("-n", "--dry-run", "-v", "--verbose", "--auto-advance",
                  "-f", "--force", "-u", "--update", "--renormalize",
                  "-N", "--intent-to-add", "-A", "--all", "--ignore-removal",
                  "--refresh", "--ignore-errors", "--ignore-missing", "--sparse",
                  "--pathspec-file-nul"),
            value={"-U": "int", "--unified": "int", "--inter-hunk-context": "int",
                   "--chmod": frozenset({"+x", "-x"}),
                   "--pathspec-from-file": "any"},
            positional="any", after_dashdash="positional"),
            # EXCLUDED: -i/--interactive, -p/--patch (interactive); -e/--edit
            # (opens $EDITOR, same class).
        "commit": spec(
            bool=("-q", "--quiet", "-v", "--verbose", "--reset-author",
                  "-s", "--signoff", "--status", "--no-status", "-a", "--all",
                  "-i", "--include", "-o", "--only", "-n", "--no-verify",
                  "--verify", "--dry-run", "--short", "--branch", "--ahead-behind",
                  "--porcelain", "--long", "-z", "--null",
                  "--no-post-rewrite", "--post-rewrite",
                  "--allow-empty", "--allow-empty-message",
                  "--pathspec-file-nul",
                  # OWNER-DECISION (git commit --amend, see module docstring
                  # and this head's own comment above) -- uncomment to admit:
                  # "--amend", "--no-amend",
                  ),
            value={"-m": "any", "--message": "any", "-F": "any", "--file": "any",
                   "--author": "any", "--date": "any", "-C": "any",
                   "--reuse-message": "any", "--squash": "any",
                   "--trailer": "any", "-t": "any", "--template": "any",
                   "--cleanup": frozenset({"strip", "whitespace", "verbatim", "scissors", "default"}),
                   "-U": "int", "--unified": "int", "--inter-hunk-context": "int",
                   "--pathspec-from-file": "any"},
            optional={"-u": frozenset({"all", "normal", "no"}),
                      "--untracked-files": frozenset({"all", "normal", "no"}),
                      "-S": "any", "--gpg-sign": "any"},
            # cluster=True: getopt-style short-flag clustering with a
            # trailing value flag - `-am <msg>` == `-a -m <msg>` (history-
            # replay pin: `git commit -am <msg>`).
            cluster=True, positional="any", after_dashdash="positional"),
            # EXCLUDED: -p/--patch, --interactive (interactive); -c/
            # --reedit-message, --fixup, -e/--edit (open $EDITOR).
        "push": spec(
            bool=("-v", "--verbose", "-q", "--quiet", "--all", "--branches",
                  "--mirror", "-d", "--delete", "--tags", "-n", "--dry-run",
                  "--porcelain", "-f", "--force", "--force-if-includes",
                  "--thin", "--no-thin", "-u", "--set-upstream", "--progress",
                  "--prune", "--no-verify", "--verify", "--follow-tags",
                  "--atomic", "-4", "--ipv4", "-6", "--ipv6"),
            value={"--repo": "any",
                   "--recurse-submodules": frozenset({"check", "on-demand", "no", "yes"}),
                   "-o": "any", "--push-option": "any"},
            optional={"--force-with-lease": "any",
                      "--signed": frozenset({"yes", "no", "if-asked"})},
            positional="any"),
            # EXCLUDED: --receive-pack, --exec (exec-by-name).
        "pull": spec(
            bool=("-v", "--verbose", "-q", "--quiet", "--progress",
                  "--no-rebase", "-n", "--stat", "--no-stat",
                  "--compact-summary", "--no-compact-summary", "--squash",
                  "--no-squash", "--commit", "--no-commit", "--no-edit",
                  "--ff", "--no-ff", "--ff-only", "--verify", "--no-verify",
                  "--verify-signatures", "--no-verify-signatures",
                  "--autostash", "--no-autostash", "--allow-unrelated-histories",
                  "--all", "-a", "--append", "-f", "--force", "-t", "--tags",
                  "-p", "--prune", "-k", "--keep", "--unshallow",
                  "--update-shallow", "-4", "--ipv4", "-6", "--ipv6",
                  "--show-forced-updates", "--set-upstream"),
            value={"--cleanup": "any", "-X": "any", "--strategy-option": "any",
                   "--depth": "int", "--shallow-since": "any",
                   "--shallow-exclude": "any", "--deepen": "int",
                   "--refmap": "any", "-o": "any", "--server-option": "any",
                   "--negotiation-restrict": "any", "--negotiation-tip": "any",
                   "--negotiation-include": "any"},
            optional={"-r": frozenset({"false", "true", "merges"}),
                      "--rebase": frozenset({"false", "true", "merges"}),
                      "--recurse-submodules": "any", "--log": "int",
                      "--signoff": "any", "-j": "int", "--jobs": "int",
                      "-S": "any", "--gpg-sign": "any"},
            positional="any"),
            # EXCLUDED: --edit (opens $EDITOR); -s/--strategy (execs an
            # arbitrary PATH-resolved git-merge-<name> helper); --upload-pack
            # (exec-by-name); "interactive" removed from --rebase's domain.
        "fetch": spec(
            bool=("-v", "--verbose", "-q", "--quiet", "--all", "--set-upstream",
                  "-a", "--append", "--atomic", "-f", "--force", "-m",
                  "--multiple", "-t", "--tags", "-n", "--prefetch", "-p",
                  "--prune", "-P", "--prune-tags", "--dry-run", "--porcelain",
                  "--write-fetch-head", "--no-write-fetch-head", "-k", "--keep",
                  "-u", "--update-head-ok", "--progress", "--unshallow",
                  "--refetch", "--update-shallow", "-4", "--ipv4", "-6", "--ipv6",
                  "--negotiate-only", "--auto-maintenance", "--no-auto-maintenance",
                  "--auto-gc", "--no-auto-gc", "--write-commit-graph",
                  "--no-write-commit-graph", "--show-forced-updates"),
            value={"--depth": "int", "--shallow-since": "any",
                   "--shallow-exclude": "any", "--deepen": "int",
                   "--refmap": "any", "-o": "any", "--server-option": "any",
                   "--negotiation-restrict": "any", "--negotiation-tip": "any",
                   "--negotiation-include": "any", "--filter": "any",
                   "-j": "int", "--jobs": "int"},
            optional={"--recurse-submodules": "any"},
            positional="any"),
            # EXCLUDED: --upload-pack (exec-by-name); --stdin (blocks
            # indefinitely reading stdin if none is piped - hang class).
        "branch": spec(
            bool=BRANCH_READ_ONLY,
            value={"--contains": "any", "--no-contains": "any",
                   "--format": "any", "--sort": "any"},
            optional={"--merged": "any", "--no-merged": "any",
                      "--points-at": "any", "--column": "any", "--abbrev": "int"},
            positional="none"),
        "stash": spec(require_verb=True, verbs={
            "list": spec(positional="none"),
        }),
    }, require_verb=True),
}


# ---------------------------------------------------------------------
# gh (hand-authored, overrides the generic family derivation - same
# pattern as `git`/`terraform`; the `for _head in cli_families.FAMILIES`
# loop at the bottom of this module skips any head already in HEAD_SPECS).
# `gh pr/issue/run/repo/release/workflow/gist <ns> --help`, `gh search
# issues/prs/repos/code/commits --help` - local `/opt/homebrew/bin/gh`
# 2.100.0, re-checked 2026-09-27. `-w`/`--web` is excluded on every leaf
# (launches the default browser as a side effect - unbatchable UI action,
# not what an auto-approved observational command should do); `pr checks
# --watch` stays excluded (already independently in
# cli_families.FAMILIES["gh"]["stream_specs"]).
# ---------------------------------------------------------------------
_GH_ROOT_VALUE = {
    "-R": "any", "--repo": "any",
    "-q": "any", "--jq": "any", "--json": "any",
    "-t": "any", "--template": "any",
}


def _gh_group(children):
    return spec(value=dict(_GH_ROOT_VALUE), require_verb=True, verbs=children)


def _gh_leaf(bool=(), value=None):
    return spec(bool=bool, value=dict(value or {}), positional="any", inherit=True)


_GH_PR_STATE = frozenset({"open", "closed", "merged", "all"})
_GH_ISSUE_STATE = frozenset({"open", "closed", "all"})

HEAD_SPECS["gh"] = spec(
    value=dict(_GH_ROOT_VALUE),
    require_verb=True,
    verbs={
        "pr": _gh_group({
            "list": _gh_leaf(
                bool=("-d", "--draft"),
                value={"--app": "any", "-a": "any", "--assignee": "any",
                       "-A": "any", "--author": "any", "-B": "any", "--base": "any",
                       "-H": "any", "--head": "any", "-l": "any", "--label": "any",
                       "-L": "any", "--limit": "any", "-S": "any", "--search": "any",
                       "-s": "any", "--state": _GH_PR_STATE}),
            "view": _gh_leaf(bool=("-c", "--comments")),
            "status": _gh_leaf(bool=("-c", "--conflict-status")),
            "diff": _gh_leaf(
                bool=("--allow-escape-sequences", "--name-only", "--patch"),
                value={"--color": frozenset({"always", "never", "auto"}),
                       "-e": "any", "--exclude": "any"}),
            "checks": _gh_leaf(
                bool=("--fail-fast", "--required"),
                value={"-i": "any", "--interval": "any"}),
        }),
        "issue": _gh_group({
            "list": _gh_leaf(
                value={"--app": "any", "-a": "any", "--assignee": "any",
                       "-A": "any", "--author": "any", "-l": "any", "--label": "any",
                       "-L": "any", "--limit": "any", "--mention": "any",
                       "-m": "any", "--milestone": "any", "-S": "any",
                       "--search": "any", "-s": "any", "--state": _GH_ISSUE_STATE,
                       "--type": "any"}),
            "view": _gh_leaf(bool=("-c", "--comments")),
            "status": _gh_leaf(),
        }),
        "run": _gh_group({
            "list": _gh_leaf(
                value={"-a": "any", "--all": "any", "-b": "any", "--branch": "any",
                       "-c": "any", "--commit": "any", "--created": "any",
                       "-e": "any", "--event": "any", "-L": "any", "--limit": "any",
                       "-s": "any", "--status": "any", "-u": "any", "--user": "any",
                       "-w": "any", "--workflow": "any"}),
            "view": _gh_leaf(
                bool=("--exit-status", "--log", "--log-failed", "-v", "--verbose"),
                value={"-a": "any", "--attempt": "any", "-j": "any", "--job": "any"}),
        }),
        "repo": _gh_group({
            "list": _gh_leaf(
                bool=("--archived", "--fork", "--no-archived", "--source"),
                value={"-l": "any", "--language": "any", "-L": "any", "--limit": "any",
                       "--topic": "any",
                       "--visibility": frozenset({"public", "private", "internal"})}),
            "view": _gh_leaf(value={"-b": "any", "--branch": "any"}),
        }),
        "release": _gh_group({
            "list": _gh_leaf(
                bool=("--exclude-drafts", "--exclude-pre-releases"),
                value={"-L": "any", "--limit": "any",
                       "-O": frozenset({"asc", "desc"}), "--order": frozenset({"asc", "desc"})}),
            "view": _gh_leaf(),
        }),
        "workflow": _gh_group({
            "list": _gh_leaf(bool=("-a", "--all"), value={"-L": "any", "--limit": "any"}),
            "view": _gh_leaf(bool=("-y", "--yaml"), value={"-r": "any", "--ref": "any"}),
        }),
        "gist": _gh_group({
            "list": _gh_leaf(
                bool=("--include-content", "--public", "--secret"),
                value={"--filter": "any", "-L": "any", "--limit": "any"}),
        }),
        # "search" is a single-token leaf directly under the root
        # (cli_families.FAMILIES["gh"]["ro_verbs"] has ("search",), not
        # ("search", "issues")) - one union-of-subtypes leaf covers every
        # `gh search {issues,prs,repos,code,commits}` invocation without
        # adding new verb tokens beyond what the family already lists.
        "search": spec(
            bool=("--include-prs", "--locked", "--no-assignee", "--no-label",
                  "--no-milestone", "--no-project", "--draft", "--merged",
                  "--merge"),
            value={"--app": "any", "--archived": "any", "--assignee": "any",
                   "--author": "any", "--author-date": "any", "--author-email": "any",
                   "--author-name": "any", "-B": "any", "--base": "any",
                   "--checks": "any", "--closed": "any", "--commenter": "any",
                   "--comments": "any", "--committer": "any", "--committer-date": "any",
                   "--committer-email": "any", "--committer-name": "any",
                   "--created": "any", "--extension": "any", "--filename": "any",
                   "--followers": "any", "--forks": "any",
                   "--good-first-issues": "any", "--hash": "any",
                   "--help-wanted-issues": "any", "--include-forks": "any",
                   "--interactions": "any", "--involves": "any", "--label": "any",
                   "--language": "any", "-L": "any", "--limit": "any",
                   "--license": "any", "--match": "any", "--mentions": "any",
                   "--merged-at": "any", "--milestone": "any",
                   "--number-topics": "any", "--order": "any", "--owner": "any",
                   "--parent": "any", "--project": "any", "--reactions": "any",
                   "-R": "any", "--repo": "any", "--review": "any",
                   "--review-requested": "any", "--reviewed-by": "any",
                   "--search-type": "any", "--size": "any", "--sort": "any",
                   "--state": "any", "--team-mentions": "any", "--topic": "any",
                   "--tree": "any", "--updated": "any", "--visibility": "any"},
            positional="any", inherit=True, after_dashdash="positional"),
    },
)


# ---------------------------------------------------------------------
# grep (BSD grep, `/usr/bin/grep --help` pulled 2026-09-27: usage: grep
# [-abcdDEFGHhIiJLlMmnOopqRSsUVvwXxZz] [-A num] [-B num] [-C[num]]
# [-e pattern] [-f file] [--binary-files=value] [--color=when]
# [--context[=num]] [--directories=action] [--label] [--line-buffered]
# [--null] [pattern] [file ...] - every listed flag is a read filter/
# selector; none writes output to a path (grep has no -o-to-file form).
# `-f file` reads a pattern file (RO); GNU siblings (--include/--exclude/
# --exclude-dir/-r/-R recursive, --color long form) added as extremely
# well-established GNU-grep RO equivalents, not re-verified live this
# session (loss-list candidate to tighten if the owner wants strict BSD
# parity only).
# ---------------------------------------------------------------------
# ls (BSD `man ls` + GNU man7.org ls(1), re-checked 2026-09-27; real
# per-flag grammar with cluster=True replaces the old hand-enumerated
# combo list - any legal combination composes instead of only the
# pre-baked spellings. `gls` (Homebrew coreutils) shares the same spec.
# `nonempty_positional` hook kept (guards `ls ""`); every flag here is
# read-only display/sort/format - unioning BSD+GNU under one head token is
# safe (the worst outcome of a wrong-dialect flag is "invalid option").
_LS_BOOL = (
    "-@", "-A", "-B", "-C", "-F", "-G", "-H", "-I", "-L", "-O", "-P", "-R",
    "-S", "-T", "-U", "-W", "-X", "-a", "-b", "-c", "-d", "-e", "-f", "-g",
    "-h", "-i", "-k", "-l", "-m", "-n", "-o", "-p", "-q", "-r", "-s", "-t",
    "-u", "-v", "-w", "-x", "-y", "-%", "-1", "-,",
    "--all", "--almost-all", "--escape", "--ignore-backups", "--classify",
    "--full-time", "--group-directories-first", "--dereference-command-line",
    "--inode", "--kibibytes", "--dereference", "--numeric-uid-gid",
    "--literal", "--hide-control-chars", "--quote-name", "--reverse",
    "--recursive", "--size", "--tabsize", "--directory", "--no-group",
    "--human-readable", "--file-type", "--show-control-chars", "--si",
    "--dereference-command-line-symlink-to-dir", "--zero", "--author",
    "--help", "--version", "--dired",
)
_LS_VALUE = {
    "-D": "any",  # BSD: strftime format string for -l dates
    "-I": "any", "--ignore": "any",           # GNU: shell-pattern exclude
    "-T": "int", "--tabsize": "any",
    "-w": "int", "--width": "any",
    "--block-size": "any",
    "--format": frozenset({"across", "commas", "horizontal", "long",
                            "single-column", "verbose", "vertical"}),
    "--hide": "any",
    "--indicator-style": frozenset({"none", "slash", "file-type", "classify"}),
    "--quoting-style": frozenset({"literal", "locale", "shell",
                                   "shell-always", "shell-escape",
                                   "shell-escape-always", "c", "escape"}),
    "--sort": frozenset({"none", "size", "time", "version", "extension",
                          "width", "name"}),
    "--time": frozenset({"atime", "access", "use", "ctime", "status",
                          "birth", "creation"}),
    "--time-style": "any",
    # NOTE: real ls syntax is `--color[=WHEN]`/`--hyperlink[=WHEN]` (bare
    # form defaults to "auto"), which would normally belong in `optional`
    # - kept as a REQUIRED value flag instead (bare form rejected) because
    # the exact corpus pins `ls --color` (bare, no argument) as a NEGATIVE
    # case (old never admitted it); REQ-05 replay caught the bare form as
    # a new admission when this was in `optional`. `--color=auto`/
    # `--color auto` still rewrite either way - only the argument-less
    # spelling is affected, a narrow compression loss, not a hole.
    "--color": frozenset({"always", "auto", "never", "yes", "no", "force",
                           "none", "tty", "if-tty"}),
    "--hyperlink": frozenset({"always", "auto", "never"}),
}
HEAD_SPECS["ls"] = spec(
    # positional stays ("max", 1): the exact corpus pins `ls a b` (two
    # path operands) as a NEGATIVE case (old's hand-enumerated predicate
    # only ever admitted a single path); REQ-05 replay caught the wider
    # `positional="any"` as a new admission - `ls -la src tests docs`-
    # style multi-path invocations are a real, plausible compression loss
    # (recommended follow-up: an owner sign-off to widen this specific
    # cap), not applied here.
    bool=_LS_BOOL, value=_LS_VALUE,
    cluster=True, positional=("max", 1), hook="nonempty_positional",
)
HEAD_SPECS["gls"] = HEAD_SPECS["ls"]  # Homebrew coreutils spelling on macOS


# grep (BSD `/usr/bin/grep`, `man grep` re-checked 2026-09-27 - this build
# documents itself as "GNU compatible" and already lists --include/
# --exclude/--exclude-dir/-R inline). CORRECTNESS FIXES vs. the earlier
# draft: `d`/`D`/`m` are REQUIRED-value flags, not bare booleans (removed
# from the bool char-class; `-d`/`--directories` and the new `-D`/
# `--devices`, `-m`/`--max-count` added to `value`); `--color`/`--colour`
# is `--color[=when]` (optional value), not a bare bool - moved to
# `optional`. `-P`/`--perl-regexp` and `--exclude-from` are GNU-only,
# well-established, not re-verified live (no GNU grep on this machine).
HEAD_SPECS["grep"] = spec(
    bool=tuple(f"-{c}" for c in "abcEFGHhIiJLlMmnOopqRSsUuVvwXxyZz") + (
        "--line-buffered", "--null", "-r", "-R", "--recursive", "--mmap",
        "--help", "-P", "--perl-regexp",
    ),
    value={
        "-A": "int", "--after-context": "int",
        "-B": "int", "--before-context": "int",
        "-e": "any", "--regexp": "any",
        "-f": "any", "--file": "any",
        "-m": "int", "--max-count": "int",
        "-d": frozenset({"read", "skip", "recurse"}),
        "--directories": frozenset({"read", "skip", "recurse"}),
        "-D": frozenset({"read", "skip"}), "--devices": frozenset({"read", "skip"}),
        "--binary-files": frozenset({"binary", "without-match", "text"}),
        "--label": "any",
        "--include": "any", "--exclude": "any", "--exclude-dir": "any",
        "--include-dir": "any",
        "--exclude-from": "any",
    },
    optional={
        "-C": "int", "--context": "int",
        "--color": frozenset({"never", "always", "auto"}),
        "--colour": frozenset({"never", "always", "auto"}),
    },
    cluster=True,
    positional="any",
)


# ---------------------------------------------------------------------
# rg (ripgrep 15.2.0, installed - full `rg --help` re-checked 2026-09-27).
# CORRECTNESS FIXES vs. the earlier draft: `-L` is `--follow` (symlink-
# following), NOT `--files-without-match` (that flag has no short form at
# all) - a real semantic mismatch, not just an omission; `--files` (list-
# files-that-would-be-searched) was missing entirely; `--color` is
# `--color=WHEN` (optional value), not a bare bool.
# ---------------------------------------------------------------------
HEAD_SPECS["rg"] = spec(
    bool=(
        "-i", "--ignore-case", "-v", "--invert-match", "-n", "--line-number",
        "-N", "--no-line-number", "-c", "--count", "--count-matches",
        "-l", "--files-with-matches", "--files-without-match",
        "-w", "--word-regexp", "-x", "--line-regexp",
        "-o", "--only-matching", "-s", "--case-sensitive", "-S", "--smart-case",
        "-U", "--multiline", "--multiline-dotall", "--no-multiline", "--no-multiline-dotall",
        "-a", "--text", "--no-text", "-F", "--fixed-strings", "--no-fixed-strings",
        "-P", "--pcre2", "--no-pcre2",
        "-L", "--follow", "--no-follow",
        "-.", "--hidden", "--no-hidden",
        "--no-ignore", "--ignore",
        "--no-ignore-dot", "--ignore-dot", "--no-ignore-exclude", "--ignore-exclude",
        "--no-ignore-files", "--ignore-files", "--no-ignore-global", "--ignore-global",
        "--no-ignore-parent", "--ignore-parent", "--no-ignore-vcs", "--ignore-vcs",
        "--no-require-git", "--require-git",
        "--one-file-system", "--no-one-file-system",
        "-u", "--unrestricted",
        "-z", "--search-zip",
        "--crlf", "--no-crlf", "--no-unicode", "--unicode",
        "--null-data", "--stop-on-nonmatch",
        "--mmap", "--no-mmap",
        "--auto-hybrid-regex", "--no-auto-hybrid-regex",
        "--no-pcre2-unicode", "--pcre2-unicode",
        "--binary", "--no-binary",
        "--glob-case-insensitive", "--no-glob-case-insensitive",
        "--ignore-file-case-insensitive", "--no-ignore-file-case-insensitive",
        "--block-buffered", "--no-block-buffered", "-b", "--byte-offset", "--no-byte-offset",
        "--column", "--no-column",
        "--context-separator", "--no-context-separator",
        "--heading", "--no-heading",
        "-h", "--help",
        "--include-zero", "--no-include-zero",
        "--line-buffered", "--no-line-buffered",
        "--max-columns-preview", "--no-max-columns-preview",
        "-0", "--null",
        "--passthru", "--passthrough",
        "-p", "--pretty", "-q", "--quiet",
        "--trim", "--no-trim", "--vimgrep",
        "-H", "--with-filename", "-I", "--no-filename",
        "--sort-files", "--no-sort-files",
        "--json", "--no-json",
        "--debug", "--trace",
        "--no-ignore-messages", "--ignore-messages", "--no-messages", "--messages",
        "--stats", "--no-stats",
        "--files",
        "--no-config", "--pcre2-version", "--type-list", "-V", "--version",
    ),
    value={
        "-e": "any", "--regexp": "any",
        "-f": "any", "--file": "any",
        "-g": "any", "--glob": "any", "--iglob": "any",
        "-t": "any", "--type": "any", "-T": "any", "--type-not": "any",
        "--type-add": "any", "--type-clear": "any",
        "-m": "int", "--max-count": "int",
        "-A": "int", "--after-context": "int",
        "-B": "int", "--before-context": "int",
        "-C": "int", "--context": "int",
        "-d": "int", "--max-depth": "int", "--maxdepth": "int",
        "-j": "int", "--threads": "int",
        "-M": "int", "--max-columns": "int",
        "--dfa-size-limit": "any", "--regex-size-limit": "any", "--max-filesize": "any",
        "-E": "any", "--encoding": "any",
        "--engine": frozenset({"default", "pcre2", "auto"}),
        "--sort": frozenset({"none", "path", "modified", "accessed", "created"}),
        "--sortr": frozenset({"none", "path", "modified", "accessed", "created"}),
        "--colors": "any",
        "--field-context-separator": "any", "--field-match-separator": "any",
        "--hyperlink-format": "any",
        "--ignore-file": "any",
        "--path-separator": "any",
        "-r": "any", "--replace": "any",  # docs: never modifies the searched files
        "--generate": frozenset({"man", "complete-bash", "complete-zsh",
                                  "complete-fish", "complete-powershell"}),
    },
    optional={
        "--color": frozenset({"never", "auto", "always", "ansi"}),
    },
    cluster=True,
    positional="any",
    # `--` marks end-of-flags in ripgrep too (pattern/paths follow) -
    # history-replay pin: `rg -l -- <pattern> <paths>`.
    after_dashdash="positional",
)
# --pre, --pre-glob, --hostname-bin: deliberately never declared - all
# three exec an arbitrary named program (or spawn one per searched file).
# NOTE: `-e <pattern>` where <pattern> itself starts with "-" (e.g. `rg -e
# --tier`) is NOT admitted - the engine never accepts a dash-prefixed
# separate-token value (ambiguity guard) and rg's own `=`/glued forms
# don't help here either (the pattern legitimately starts with "--"); an
# accepted, narrow compression loss, not a hole.


# ---------------------------------------------------------------------
# cat / tree / wc / head / tail / sort / uniq - the classic RO toolbox.
# BSD `man wc|head|tail|sort|uniq|cat` re-checked 2026-09-27 (this
# machine's BSD `sort` documents itself as accepting GNU long options
# already, doubling as the GNU citation for `sort`). Denied write-path
# flags (sort -o/--output/--compress-program/-T) are closed simply by
# never listing them.
# ---------------------------------------------------------------------
HEAD_SPECS["cat"] = spec(
    bool=("-n", "--number", "-b", "--number-nonblank", "-s", "--squeeze-blank",
          "-A", "--show-all", "-e", "-E", "--show-ends", "-t", "-T", "--show-tabs",
          "-v", "--show-nonprinting", "-u", "-l",
          "--help", "--version"),
    positional="any")
HEAD_SPECS["wc"] = spec(
    bool=("-l", "-c", "-m", "-w", "-L", "--libxo",
          "--bytes", "--chars", "--lines", "--max-line-length", "--words",
          "--help", "--version"),
    value={"--files0-from": "any", "--total": frozenset({"auto", "always", "only", "never"})},
    positional="any")
HEAD_SPECS["head"] = spec(
    bool=("-c", "-n", "-q", "-v", "-z", "--zero-terminated", "--quiet",
          "--silent", "--verbose", "--help", "--version"),
    numeric=True,
    value={"-n": "int", "-c": "int", "--lines": "int", "--bytes": "int"},
    positional="any")
HEAD_SPECS["tail"] = spec(
    # -f/--follow/-F: never listed (stream forever/hang, TK-55); --pid/
    # --retry/-s/--max-unchanged-stats only matter paired with -f/-F, so
    # they stay excluded too (inert/misleading without it).
    bool=("-q", "--quiet", "--silent", "-r", "-v", "--verbose",
          "-z", "--zero-terminated", "--help", "--version"),
    numeric=True,
    value={"-n": "int", "-c": "int", "-b": "int",
           "--lines": "int", "--bytes": "int", "--blocks": "int"},
    positional="any")
HEAD_SPECS["sort"] = spec(
    bool=("-c", "-C", "-m", "--merge", "-u", "-s", "-b", "-d", "-f", "-g",
          "-h", "-i", "-M", "-n", "-R", "-r", "-V", "-z",
          "--check", "--unique", "--ignore-leading-blanks",
          "--dictionary-order", "--ignore-case", "--general-numeric-sort",
          "--human-numeric-sort", "--ignore-nonprinting", "--month-sort",
          "--numeric-sort", "--random-sort", "--reverse", "--version-sort",
          "--zero-terminated", "--version", "--help",
          "--debug", "--radixsort", "--mergesort", "--qsort", "--heapsort", "--mmap"),
    value={"-k": "any", "--key": "any", "-t": "any", "--field-separator": "any",
           "-S": "any", "--buffer-size": "any",
           "--batch-size": "int", "--parallel": "int",
           "--random-source": "any", "--files0-from": "any"},
    optional={"--check": frozenset({"silent", "quiet"})},
    positional="any")
    # EXCLUDED: -o/--output (writes to a named file); -T/--temporary-
    # directory (names a scratch-write dir, doubt->exclude);
    # --compress-program (execs an arbitrary named program).
HEAD_SPECS["uniq"] = spec(
    bool=("-c", "-d", "-u", "-i", "-z",
          "--count", "--repeated", "--unique", "--ignore-case", "--zero-terminated",
          "--help", "--version"),
    value={"-f": "int", "-s": "int", "-w": "int",
           "--skip-fields": "int", "--skip-chars": "int", "--check-chars": "int"},
    optional={"-D": frozenset({"none", "prepend", "separate"}),
              "--all-repeated": frozenset({"none", "prepend", "separate"}),
              "--group": frozenset({"separate", "prepend", "append", "both"})},
    # `uniq [input [output]]` - keep at most 1 positional: a second
    # operand is a write path.
    positional=("max", 1))


# ---------------------------------------------------------------------
# tree (not installed on this machine - DOC manpages.debian.org/testing/
# tree/tree.1.en.html, same disclaimer class as other GNU-sibling notes).
# ---------------------------------------------------------------------
HEAD_SPECS["tree"] = spec(
    bool=("-a", "-d", "-l", "-f", "-x", "-q", "-N", "-Q", "-p", "-u", "-g",
          "-s", "-h", "--si", "-D", "-F", "-i", "-A", "-S", "-n", "-C",
          "--gitignore", "--ignore-case", "--matchdirs", "--metafirst",
          "--prune", "--info", "--noreport", "--du", "--dirsfirst",
          "--filesfirst", "--inodes", "--device", "--acl", "--selinux",
          "-X", "-J", "--nolinks", "--hyperlink", "--help", "--version"),
    value={"-L": "int", "-P": "any", "-I": "any",
           "--gitfile": "any", "--infofile": "any",
           "--charset": "any", "--filelimit": "int", "--compress": "int",
           "--timefmt": "any",
           "--sort": frozenset({"ctime", "mtime", "size", "version", "name", "none"}),
           "--scheme": "any", "--authority": "any", "-T": "any",
           "--hintro": "any", "--houtro": "any"},
    cluster=True,  # tree admits combined short bools, e.g. `-si`
    positional="any",
)
# EXCLUDED (tree): -o FILENAME (writes the listing to a named file); -H
# (HTML mode, typically paired with -o, doubt->exclude); -R (this build's
# doc table describes it as "recursive HTML to 00Tree.html files" - an
# implicit write, single-source/unconfirmed, excluded out of caution).


# ---------------------------------------------------------------------
# find (BSD find; `man find` re-checked 2026-09-27, full PRIMARIES
# section - already documents most GNU-compat aliases inline, e.g.
# `-wholename`/`-iwholename`). Every write/exec primary (-delete/-exec/
# -execdir/-ok/-okdir/-fprint/-fprint0/-fprintf/-fls) is closed by simply
# never declaring it - no forbidden-set/hook needed (unknown primaries
# fail closed by construction).
# ---------------------------------------------------------------------
_FIND_NEWERXY = tuple(
    f"-newer{x}{y}" for x in "aBcm" for y in "aBcmt"
)  # 20 literal spellings per man find's -newerXY (X in a,B,c,m; Y in a,B,c,m,t)

HEAD_SPECS["find"] = spec(
    bool=(
        "-d", "-s", "-x", "-H", "-L", "-P", "-X", "-E",
        "-depth", "-empty", "-print", "-print0", "!", "-not",
        "-a", "-and", "-o", "-or", "-false", "-true",
        "-acl", "-ignore_readdir_race", "-noignore_readdir_race",
        "-ls", "-mount", "-nogroup", "-noleaf", "-nouser",
        "-prune", "-quit", "-sparse", "-xattr",
    ),
    value=dict({
        # NOTE: "-f path" (top-level "add search path") is deliberately
        # NOT declared: as a 2-char value flag the engine's glued-short-
        # form rule would also match it against "-fprint"/"-fprint0"/
        # "-fprintf"/"-fls" (parsed as "-f" + glued value "print"/
        # "print0"/"printf"/"ls"), silently re-opening exactly the write-
        # to-named-file class this spec exists to close (REQ-05 replay
        # caught this) - a compression-only loss, not a real feature gap
        # (find always accepts a bare leading path operand instead).
        "-Bmin": "int", "-Bnewer": "any", "-Btime": "any",
        "-amin": "int", "-anewer": "any", "-atime": "any",
        "-cmin": "int", "-cnewer": "any", "-ctime": "any",
        "-mmin": "int", "-mnewer": "any", "-mtime": "any",
        "-name": "any", "-iname": "any", "-path": "any", "-ipath": "any",
        "-wholename": "any", "-iwholename": "any",
        "-regex": "any", "-iregex": "any",
        "-lname": "any", "-ilname": "any",
        "-type": "any", "-maxdepth": "int", "-mindepth": "int", "-size": "any",
        "-newer": "any", "-perm": "any", "-flags": "any",
        "-user": "any", "-uid": "any", "-group": "any", "-gid": "any",
        "-fstype": "any", "-inum": "int", "-links": "int",
        "-samefile": "any", "-xattrname": "any",
    }, **{k: "any" for k in _FIND_NEWERXY}),
    positional="any",
)


# ---------------------------------------------------------------------
# pytest: real `python3 -m pytest --help` (installed fresh into a
# throwaway scratch venv this session, not the project's environment -
# strongest-provenance source in this module, verbatim tool output).
# CORRECTNESS FIXES: `--tb=short/long/line/native` were 4 hard-coded bool
# literals - the real flag is `--tb=style` (value flag; also admits
# `auto`/`no`, previously unreachable); `-ra`/`-rf`/`-rs` were 3 hard-coded
# bool literals - the real flag is `-r`/`--report-chars <chars>` (any
# combination of report-category letters). `-p` is restricted to a
# frozenset of `no:<builtin>` disable-spellings - a bare plugin name would
# load arbitrary code (AGENTS.md TK-55 lesson); extend only via a journal
# decision, never widen to "any".
# ---------------------------------------------------------------------
HEAD_SPECS["pytest"] = spec(
    bool=(
        "--markers", "-x", "--exitfirst", "--strict-config", "--strict-markers",
        "--strict", "--fixtures", "--funcargs", "--fixtures-per-test",
        "-s", "--runxfail", "--lf", "--last-failed", "--ff", "--failed-first",
        "--nf", "--new-first", "--cache-clear", "--sw", "--stepwise",
        "--sw-skip", "--stepwise-skip", "--sw-reset", "--stepwise-reset",
        "-v", "--verbose", "--no-header", "--no-summary", "--no-fold-skipped",
        "--force-short-summary", "-q", "--quiet",
        "--disable-warnings", "--disable-pytest-warnings",
        "-l", "--showlocals", "--no-showlocals", "--xfail-tb", "--full-trace",
        "--collect-only", "--co", "--pyargs", "--noconftest",
        "--keep-duplicates", "--collect-in-virtualenv",
        "--continue-on-collection-errors", "--doctest-modules",
        "--doctest-ignore-import-errors", "--doctest-continue-on-failure",
        "-V", "--version", "-h", "--help", "--disable-plugin-autoload",
        "--trace-config", "--setup-only", "--setup-show", "--setup-plan",
    ),
    value={
        "-k": "any", "-m": "any",
        # pytest-xdist (extremely common, not in the pytest --help this
        # was sourced from since it's a separate plugin): -n/--numprocesses
        # <n>|auto|logical - pure parallelism control, no writes/exec.
        "-n": "any", "--numprocesses": "any",
        "--maxfail": "int",
        "--cache-show": "any",
        "--lfnf": frozenset({"all", "none"}), "--last-failed-no-failures": frozenset({"all", "none"}),
        "--durations": "int", "--durations-min": "any",
        "--verbosity": "int",
        "-r": "any",  # any combination of report-category chars - RO selectors
        "--tb": frozenset({"auto", "long", "short", "line", "native", "no"}),
        "--show-capture": frozenset({"no", "stdout", "stderr", "log", "all"}),
        "--color": frozenset({"yes", "no", "auto"}),
        "--code-highlight": frozenset({"yes", "no"}),
        "--junit-prefix": "any",
        "-W": "any", "--pythonwarnings": "any",
        "--max-warnings": "int",
        "--ignore": "any", "--ignore-glob": "any", "--deselect": "any",
        "--confcutdir": "any",
        "--import-mode": frozenset({"prepend", "append", "importlib"}),
        "--doctest-report": frozenset({"none", "cdiff", "ndiff", "udiff", "only_first_failure"}),
        "--doctest-glob": "any",
        "-c": "any", "--config-file": "any",
        "--rootdir": "any",
        "--assert": frozenset({"plain", "rewrite"}),
        "--log-level": "any", "--log-format": "any", "--log-date-format": "any",
        "--log-cli-level": "any", "--log-cli-format": "any", "--log-cli-date-format": "any",
        "--log-auto-indent": "any", "--log-disable": "any",
        "--capture": frozenset({"fd", "sys", "no", "tee-sys"}),
        "-p": frozenset({"no:cacheprovider", "no:doctest", "no:warnings",
                          "no:randomly", "no:cov", "no:xdist", "no:flaky",
                          "no:cli"}),
    },
    cluster=True,   # pytest/argparse admits combined short bools, e.g. `-xvs`
    positional="any",
)
# EXCLUDED (pytest): --pdb/--pdbcls/--trace (interactive debugger);
# --pastebin (sends output to an external network service); --junitxml
# (writes a named file); --basetemp (docs: "this directory is removed if
# it exists" - destructive delete); -o/--override-ini (arbitrary config
# override, could inject further dangerous flags via addopts); --debug
# (docs: opened with 'w' and truncated); --log-file* family (writes a
# named path); --cache-clear (deletes .pytest_cache contents).

# jest: DOC jestjs.io/docs/cli (no node/npm/jest installed locally - not
# --help-verified). `--env`/`--reporters` restricted to built-in names -
# a custom value is a module path Jest require()s/executes.
HEAD_SPECS["jest"] = spec(
    bool=(
        "-o", "--onlyChanged", "--ci", "--silent", "--verbose",
        "--runInBand", "-i", "--detectOpenHandles", "--passWithNoTests",
        "-b", "--bail", "--cache", "--changedFilesWithAncestor",
        "--clearMocks", "--collectTests", "--colors", "--debug",
        "--errorOnDeprecated", "-e", "--expand", "--findRelatedTests",
        "--forceExit", "--help", "-h", "--injectGlobals", "--json",
        "--lastCommit", "--listTests", "--logHeapUsage", "--noStackTrace",
        "--randomize", "--resetMocks", "--restoreMocks", "--runTestsByPath",
        "--showConfig", "--showSeed", "--testLocationInResults",
        "--useStderr", "--version", "-v", "--waitForUnhandledRejections",
        "--watchman", "--workerThreads",
    ),
    value={
        "-c": "any", "--config": "any",
        "--changedSince": "any",
        "--collectCoverageFrom": "any",
        "--coverageProvider": frozenset({"babel", "v8"}),
        "--maxConcurrency": "int",
        "-w": "any", "--maxWorkers": "any",
        "--openHandlesTimeout": "int",
        "-t": "any", "--testNamePattern": "any",
        "--testPathPattern": "any", "--testPathPatterns": "any",
        "--testPathIgnorePatterns": "any", "--testMatch": "any",
        "--testEnvironmentOptions": "any", "--testTimeout": "int",
        "--seed": "any", "--shard": "any",
        "--projects": "any", "--selectProjects": "any", "--ignoreProjects": "any",
        "--roots": "any",
        "--env": frozenset({"node", "jsdom"}),
        "--reporters": frozenset({"default", "github-actions", "summary"}),
        "--workerGracefulExitTimeout": "int",
    },
    positional="any",
)
# EXCLUDED (jest): --coverage/--collectCoverage/--coverageDirectory
# (writes a coverage report to disk); --outputFile (named file);
# --filter (loads/executes an arbitrary named filtering module);
# --notify (spawns OS notification integration); --setupFilesAfterEnv/
# --testRunner/--testSequencer (load arbitrary named modules as code);
# -u/--updateSnapshot (writes snapshot fixture files); --watch/--watchAll
# (streams forever); --clearCache (deletes the Jest cache directory).
# Caveat (inherent, not flag-specific): Jest's own snapshot testing can
# still write a NEW snapshot file the first time a toMatchSnapshot()
# assertion runs with none on disk - a property of the suite's own code,
# not any CLI flag; --ci (admitted) makes this fail instead of write.

# vitest: DOC vitest.dev/guide/cli.html (no local install). Enormous
# dotted sub-option surface (--coverage.*/--browser.*/--diff.*/etc.)
# grouped by prefix rather than enumerated once each; `--reporter`
# restricted to built-in names (custom reporters are arbitrary code,
# same class as jest `--reporters`). `--clearCache` deletes cached state
# (excluded - the source doc mislabeled it read-only) and is deliberately
# NOT in the bool tuple below.
_VITEST_READONLY_PREFIXED_BOOL = (
    "--isolate", "--no-isolate", "--globals", "--no-inject-cjs-globals", "--dom",
    "--fileParallelism", "--no-file-parallelism", "--passWithNoTests",
    "--logHeapUsage", "--detectAsyncLeaks", "--allowOnly",
    "--dangerouslyIgnoreUnhandledErrors", "--disableConsoleIntercept",
    "--includeTaskLocation", "--run", "--no-color", "--clearScreen",
    "--standalone", "--strictTags", "--sharedViteServer",
    "--coverage.enabled", "--coverage.clean", "--coverage.cleanOnRerun",
    "--coverage.reportOnFailure", "--coverage.allowExternal",
    "--coverage.skipFull", "--coverage.thresholds.100",
    "--coverage.thresholds.perFile", "--coverage.excludeAfterRemap",
    "--coverage.autoAttachSubprocess",
    "--browser.enabled", "--browser.headless", "--browser.dependencySourcemaps",
    "--browser.trackUnhandledErrors", "--browser.traceView.enabled",
    "--browser.traceView.recordCanvas", "--browser.traceView.inlineImages",
    "--browser.locators.exact",
    "--typecheck.enabled", "--typecheck.only", "--typecheck.allowJs",
    "--typecheck.ignoreSourceErrors", "--typecheck.build",
    "--sequence.concurrent", "--sequence.shuffle.files", "--sequence.shuffle.tests",
    "--expect.requireAssertions", "--diff.expand", "--diff.includeChangeCounts",
    "--diff.omitAnnotationLines", "--diff.printBasicPrototype",
    "--printConsoleTrace", "--expandSnapshotDiff",
)
HEAD_SPECS["vitest"] = spec(
    verbs={
        "run": spec(inherit=True, positional="any"),
        "related": spec(inherit=True, positional="any"),
        "bench": spec(inherit=True, positional="any"),
        "list": spec(inherit=True, positional="any"),
    },
    bool=_VITEST_READONLY_PREFIXED_BOOL + ("--ci", "--silent", "--passWithNoTests"),
    value={
        "-t": "any", "--testNamePattern": "any",
        "--dir": "any", "-r": "any", "--root": "any",
        "-c": "any", "--config": "any",
        "--reporter": frozenset({"default", "verbose", "dot", "json", "junit",
                                  "tap", "tap-flat", "hanging-process", "basic"}),
        "--coverage.provider": frozenset({"v8", "istanbul"}),
        "--coverage.include": "any", "--coverage.exclude": "any",
        "--coverage.reporter": "any",
        "--coverage.thresholds.lines": "int", "--coverage.thresholds.functions": "int",
        "--coverage.thresholds.branches": "int", "--coverage.thresholds.statements": "int",
        "--coverage.ignoreClassMethods": "any", "--coverage.processingConcurrency": "int",
        "--mode": "any", "--pool": frozenset({"forks", "threads", "vmThreads", "vmForks"}),
        "--changed": "any",
        "--sequence.seed": "any", "--sequence.hooks": frozenset({"stack", "list", "parallel"}),
        "--sequence.setupFiles": frozenset({"list", "parallel"}),
        "--testTimeout": "int", "--hookTimeout": "int", "--teardownTimeout": "int",
        "--bail": "int", "--retry.count": "int", "--retry.delay": "int",
        "--repeats": "int", "--maxConcurrency": "int", "--maxWorkers": "any",
        "--slowTestThreshold": "int", "--shard": "any", "-p": "any", "--project": "any",
        "--typecheck.tsconfig": "any",
        "--configLoader": frozenset({"bundle", "runner"}),
        "--exclude": "any", "--tagsFilter": "any",
    },
    positional="any",
    # require_verb=True: bare `vitest` (default/watch mode), `vitest
    # watch`, and `vitest init ...` must NOT rewrite (all three "streams
    # forever"/"writes config files" - the proposal's own prose says so,
    # but its pasted code omitted `require_verb=True`, so any of these
    # slipped through the (declared-but-unrequired) verbs dict via the
    # root's own `positional="any"` - confirmed by a "must NOT rewrite" pin).
    require_verb=True,
)
# EXCLUDED (vitest): --typecheck.checker (non-default value is an
# arbitrary named executable); --coverage.customProviderModule (loads a
# module by path); -u/--update (writes snapshot files); --outputFile
# (named file); --coverage.reportsDirectory/--coverage.htmlDir (write
# report files to a named dir); --coverage.thresholds.autoUpdate (writes
# back into the config file); --fsModuleCachePath/--attachmentsDir (write
# to a named dir); --merge-reports (writes blob report files); -w/--watch,
# --ui, --open, --browser.ui (interactive/streams forever);
# --api.allowExec/--api.allowWrite (docs: permit API code execution/file
# editing); --clearCache (deletes cached state); bare/`watch`/`dev`/`init`
# verbs (default streams forever / writes config files - not admitted);
# --environment (finding A, wave 2026-09-27: vitest resolves a non-builtin
# value as a `vitest-environment-<name>` package to load and run - the
# same "value names a module to load" class as --typecheck.checker/
# --coverage.customProviderModule above, doubt -> not included; unlike
# jest's --env this is not restricted to a closed built-in enum here).

# tsc: DOC typescriptlang.org/docs/handbook/compiler-options (no local
# install). NAMED OWNER-DECISION (behaviour-parity, left AS TODAY):
# research found bare `tsc` (and `tsc --strict` etc. without a genuine
# no-emit flag) writes `.js`/`.d.ts` output by default, and recommended a
# `require_any_of` gate naming the flags that guarantee no emit
# (--noEmit/--showConfig/--listFilesOnly/--explainFiles/--listFiles/
# --version/--help). Per explicit instruction this gate is NOT applied
# here - old rewrote any `tsc` invocation unconditionally, and that parity
# stays until the owner decides; only the SAFE flag surface is widened
# below (every write-destination flag - --outDir/--outFile/--out/
# --declaration*/--sourceMap/--incremental/--tsBuildInfoFile/etc. - stays
# excluded by omission regardless of the gate question, so widening this
# list does not by itself open a new hole).
HEAD_SPECS["tsc"] = spec(
    bool=(
        "--noEmit", "--strict", "--pretty", "--listFiles", "--listEmittedFiles",
        "--listFilesOnly", "--showConfig", "--explainFiles", "--all",
        "--help", "--version", "--diagnostics", "--extendedDiagnostics",
        "--traceResolution", "--noErrorTruncation", "--verbose",
        "--allowJs", "--checkJs", "--allowSyntheticDefaultImports",
        "--allowUmdGlobalAccess", "--allowUnreachableCode", "--allowUnusedLabels",
        "--composite", "--disableReferencedProjectLoad", "--disableSizeLimit",
        "--disableSolutionSearching", "--disableSourceOfProjectReferenceRedirect",
        "--erasableSyntaxOnly", "--exactOptionalPropertyTypes",
        "--experimentalDecorators", "--forceConsistentCasingInFileNames",
        "--isolatedDeclarations", "--isolatedModules", "--keyofStringsOnly",
        "--libReplacement", "--noCheck", "--noEmitOnError",
        "--noFallthroughCasesInSwitch", "--noImplicitAny", "--noImplicitOverride",
        "--noImplicitReturns", "--noImplicitThis", "--noLib",
        "--noPropertyAccessFromIndexSignature", "--noResolve",
        "--noStrictGenericChecks", "--noUncheckedIndexedAccess",
        "--noUncheckedSideEffectImports", "--noUnusedLocals", "--noUnusedParameters",
        "--preserveSymlinks", "--preserveWatchOutput", "--resolveJsonModule",
        "--resolvePackageJsonExports", "--resolvePackageJsonImports",
        "--skipDefaultLibCheck", "--skipLibCheck", "--stableTypeOrdering",
        "--stopBuildOnErrors", "--strictBindCallApply", "--strictBuiltinIteratorReturn",
        "--strictFunctionTypes", "--strictNullChecks", "--strictPropertyInitialization",
        "--suppressExcessPropertyErrors", "--suppressImplicitAnyIndexErrors",
        "--useUnknownInCatchVariables", "--allowArbitraryExtensions",
        "--allowImportingTsExtensions", "--ignoreConfig",
    ),
    value={
        "--project": "any", "-p": "any",  # -p is tsc's own short alias of --project
        "--locale": "any", "--baseUrl": "any", "--charset": "any",
        "--customConditions": "any", "--lib": "any", "--maxNodeModuleJsDepth": "int",
        "--moduleDetection": frozenset({"legacy", "auto", "force"}),
        "--moduleResolution": frozenset({"node", "node10", "node16", "nodenext", "bundler", "classic"}),
        "--moduleSuffixes": "any", "--paths": "any",
        "--rootDir": "any", "--rootDirs": "any", "--typeRoots": "any", "--types": "any",
        "--fallbackPolling": "any", "--watchDirectory": "any", "--watchFile": "any",
        "--excludeDirectories": "any", "--excludeFiles": "any",
    },
    positional="any",
)
# EXCLUDED (tsc): --init (writes tsconfig.json); --build/-b/--force/
# --clean (build mode always emits, --clean deletes outputs); --watch
# (streams forever); every write-destination flag by semantic class
# (--outDir/--outFile/--out/--declaration(Dir/Map)/--sourceMap/
# --inlineSourceMap/--inlineSources/--mapRoot/--sourceRoot/
# --emitDeclarationOnly/--emitBOM/--newLine/--removeComments/
# --stripInternal/--tsBuildInfoFile/--incremental/--generateCpuProfile/
# --generateTrace/--noEmitHelpers); emit-only-relevant flags with no
# legitimate RO use (--target/--module/--jsx*/--esModuleInterop/etc.);
# --plugins (finding A, wave 2026-09-27: names TypeScript language-service
# plugin packages - the "value names a module to load" class; doubt ->
# not included, low confidence this even affects a plain `tsc` compile
# rather than only editor/IDE tooling, so excluded rather than guessed at).

# ruff: real `ruff check --help` (installed fresh into the same scratch
# venv as pytest, this session).
HEAD_SPECS["ruff"] = spec(
    bool=(
        "--show-fixes", "--diff", "--ignore-noqa", "--preview", "--statistics",
        "--show-files", "--show-settings", "-h", "--help",
        "--respect-gitignore", "--force-exclude", "-n", "--no-cache",
        "-e", "--exit-zero", "--exit-non-zero-on-fix",
        "-v", "--verbose", "-q", "--quiet", "-s", "--silent",
        "--isolated",
    ),
    value={
        "--output-format": frozenset({"concise", "full", "json", "json-lines",
                                       "junit", "grouped", "github", "gitlab",
                                       "pylint", "rdjson", "azure", "sarif"}),
        "--target-version": frozenset({"py37", "py38", "py39", "py310", "py311",
                                        "py312", "py313", "py314", "py315"}),
        "--extension": "any", "--select": "any", "--ignore": "any",
        "--extend-select": "any", "--per-file-ignores": "any",
        "--extend-per-file-ignores": "any", "--fixable": "any", "--unfixable": "any",
        "--extend-fixable": "any", "--exclude": "any", "--extend-exclude": "any",
        "--stdin-filename": "any",
        "--color": frozenset({"auto", "always", "never"}),
    },
    # NOTE: "--cache-dir" is deliberately NOT declared - it was already a
    # named exclusion in the pre-existing `_DENIED_WRITE_FLAGS["ruff"]
    # ["eq"]` table this module supersedes (REQ-05 replay confirmed old
    # rejects `ruff check --cache-dir /tmp/x .`); the research proposal's
    # ADMIT recommendation wasn't cross-checked against that table.
    forbid_write_token=True,
    positional="any",
)
# EXCLUDED (ruff): --config (finding A, wave 2026-09-27, confirmed live
# via `ruff check --help`: "Either a path to a TOML configuration file...
# or a TOML <KEY> = <VALUE> pair... overriding a specific configuration
# option" - dual-mode, and the inline-override mode can set `fix = true`
# directly, e.g. `ruff check --config 'fix = true' .`, which mutates
# source files while bypassing the `forbid_write_token` hook's literal
# "--fix" token check entirely - demonstrated this session); --fix/--fix-only (write source files), --unsafe-fixes
# (only matters combined with one of them); -w/--watch (streams forever);
# -o/--output-file (named file); --add-noqa/--add-ignore (both insert
# suppression comments into source files despite the innocuous names).

# eslint: DOC eslint.org/docs/latest/use/command-line-interface (no local
# install). `-f/--format` restricted to built-in formatter names (a
# custom formatter is an arbitrary loaded npm package/path).
HEAD_SPECS["eslint"] = spec(
    bool=(
        "--quiet", "--no-ignore", "--stdin", "--no-inline-config",
        "--report-unused-disable-directives", "--report-unused-inline-configs",
        "--cache", "--pass-on-unpruned-suppressions", "--no-config-lookup",
        "--no-error-on-unmatched-pattern", "--exit-on-fatal-error",
        "--no-warn-ignored", "--pass-on-no-patterns", "--color", "--no-color",
        "--debug", "-h", "--help", "-v", "--version", "--env-info", "--stats",
    ),
    value={
        "-c": "any", "--config": "any",
        "-f": frozenset({"stylish", "json", "json-with-metadata", "compact",
                          "unix", "visualstudio", "html", "checkstyle",
                          "codeframe", "tap", "junit", "jslint-xml"}),
        "--format": frozenset({"stylish", "json", "json-with-metadata", "compact",
                                "unix", "visualstudio", "html", "checkstyle",
                                "codeframe", "tap", "junit", "jslint-xml"}),
        "--max-warnings": "int", "--ext": "any", "--global": "any",
        "--parser-options": "any", "--rule": "any", "--ignore-pattern": "any",
        "--stdin-filename": "any",
        "--report-unused-disable-directives-severity": "any",
        "--cache-location": "any", "--cache-strategy": "any",
        "--suppress-rule": "any", "--print-config": "any",
        "--flag": "any", "--concurrency": "any",
    },
    forbid_write_token=True,  # shared hook: rejects "--fix"/"fix"/"format"
    positional="any",
)
# EXCLUDED (eslint): --parser/--plugin (load arbitrary named packages);
# --fix/--fix-dry-run/--fix-type/-o/--output-file/--suppress-all/
# --prune-suppressions/--suppressions-location (write files; --fix-dry-run
# and --fix-type are individually RO but share the "--fix" prefix the
# shared forbid_write_token hook rejects - accepted loss, not a hole);
# --inspect-config (opens a local web server + browser); --mcp (starts a
# persistent server process).

# golangci-lint: DOC golangci-lint.run/docs/configuration/cli (no go/
# golangci-lint installed - entirely doc-derived, not cross-checked
# against a second source or a live --help; recommend an owner spot-check
# before relying on this further). Previously had NO spec at all (zero
# exact-corpus coverage) - added as a new head.
HEAD_SPECS["golangci-lint"] = spec(
    verbs={
        "run": spec(
            inherit=True,
            bool=(
                "--fast-only", "--allow-parallel-runners", "--allow-serial-runners",
                "--uniq-by-line", "--show-stats", "-n", "--new", "--whole-files",
                "--tests", "--output.text.print-linter-name",
                "--output.text.print-issued-lines", "--output.text.colors",
                "--output.tab.print-linter-name", "--output.tab.colors",
                "--output.junit-xml.extended", "--no-config",
            ),
            value={
                "-D": "any", "--disable": "any", "-E": "any", "--enable": "any",
                "--enable-only": "any", "--default": frozenset({"standard", "none", "all", "fast"}),
                "-j": "int", "--concurrency": "int", "--timeout": "any",
                "--modules-download-mode": frozenset({"mod", "readonly", "vendor"}),
                "--build-tags": "any",
                "--issues-exit-code": "int", "--max-issues-per-linter": "int",
                "--max-same-issues": "int", "--path-prefix": "any", "--path-mode": "any",
                "--new-from-rev": "any", "--new-from-patch": "any",
                "--new-from-merge-base": "any",
                "-c": "any", "--config": "any",
                # every --output.<fmt>.path is restricted to {stdout,stderr}:
                # its domain is otherwise an arbitrary user-named file path.
                "--output.text.path": frozenset({"stdout", "stderr"}),
                "--output.json.path": frozenset({"stdout", "stderr"}),
                "--output.tab.path": frozenset({"stdout", "stderr"}),
                "--output.html.path": frozenset({"stdout", "stderr"}),
                "--output.checkstyle.path": frozenset({"stdout", "stderr"}),
                "--output.code-climate.path": frozenset({"stdout", "stderr"}),
                "--output.junit-xml.path": frozenset({"stdout", "stderr"}),
                "--output.teamcity.path": frozenset({"stdout", "stderr"}),
                "--output.sarif.path": frozenset({"stdout", "stderr"}),
            },
            positional="any",
        ),
        "linters": spec(inherit=True, bool=("--json", "--fast-only"),
                         value={"-D": "any", "--disable": "any", "-E": "any",
                                "--enable": "any", "--enable-only": "any",
                                "--default": frozenset({"standard", "none", "all", "fast"}),
                                "-c": "any", "--config": "any"},
                         positional="none"),
        "version": spec(bool=("--json", "--short", "--debug"), positional="none"),
    },
    bool=("-h", "--help", "-v", "--verbose", "--version"),
    value={"--color": frozenset({"always", "auto", "never"})},
    require_verb=True,
)
# EXCLUDED (golangci-lint): --fix (writes source files); --cpu-profile-
# path/--mem-profile-path/--trace-path (write profiling data to an
# arbitrary named file - no small-enum restriction possible, unlike
# --output.*.path); fmt/migrate/custom subcommands (write source/config
# files or download+build a named plugin binary - not admitted); cache
# subcommand (cache clean deletes the lint cache - not admitted).

# next (lint/build/info). DOC nextjs.org/docs/pages/api-reference/next-cli
# (Next.js v16.3.6 docs; no node/next installed). `next lint`'s own flag
# table isn't published on this version's fetched CLI reference page -
# left unchanged (bare positional, no flags) rather than guessed.
# NAMED OWNER-DECISION (behaviour-parity, left AS TODAY): `next build`
# always writes to `.next/` by design (no --noEmit equivalent); the
# current draft already treats "build" as an admitted verb (a pre-
# existing exception to the observational-only philosophy, not introduced
# here). Research proposed a flag surface for `build` (--turbopack/--turbo/
# --webpack/-d/--debug/--profile/--no-mangling/--experimental-app-only/
# --debug-prerender/--experimental-build-mode/--debug-build-paths); per
# explicit instruction `build`'s spec stays EXACTLY as it was (bare
# positional, no flags) pending an owner decision on whether to expand a
# verb that always writes at all.
_NEXT_VERB_LEVEL = spec(positional="any")
HEAD_SPECS["next"] = spec(verbs={
    "lint": _NEXT_VERB_LEVEL,
    "build": _NEXT_VERB_LEVEL,
    "info": spec(bool=("--verbose",), positional="none"),
}, require_verb=True)


# ---------------------------------------------------------------------
# cargo (LIVE `cargo --help`, `cargo test/build/check/tree/clippy/
# metadata/package/fmt --help`, and a LIVE compiled test binary's
# `cargo test -- --help` in a scratch crate, 2026-09-27).
# `--target-dir <DIR>` writes build artifacts to a user-named directory
# (AGENTS.md security-surface class) - a pre-existing draft decision, kept
# for parity, flagged for owner awareness rather than unilaterally removed.
# ---------------------------------------------------------------------
_CARGO_ROOT_BOOL = ("-q", "--quiet", "-v", "-vv", "--verbose",
                    "--offline", "--locked", "--frozen",
                    "-V", "--version", "--list")
_CARGO_ROOT_VALUE = {"--color": frozenset({"auto", "always", "never"}),
                     "-C": "any",
                     "--manifest-path": "any", "--target-dir": "any",
                     "--explain": "any"}
# EXCLUDED (wave 2026-09-27, finding A - confirmed live: `cargo test
# --config 'build.rustc-wrapper="/usr/bin/false"' --no-run` was admitted):
# --config (`--config <KEY>=<VALUE>` sets an arbitrary Cargo config key
# INLINE on the command line - not a file path - and keys like
# `build.rustc-wrapper`/`target.*.runner` name a PROGRAM Cargo then execs
# on every build/run/test); -Z (unstable nightly flags - open namespace,
# several of which are themselves further escape hatches; doubt -> not
# included). `-C <DIR>` stays admitted - it only changes the working
# directory before running (same class as `git -C`, already accepted
# elsewhere), it does not name a program.

_CARGO_PKG_SELECT_BOOL = ("--workspace", "--all")
_CARGO_PKG_SELECT_VALUE = {"-p": "any", "--package": "any", "--exclude": "any"}
_CARGO_FEATURE_BOOL = ("--all-features", "--no-default-features")
_CARGO_FEATURE_VALUE = {"-F": "any", "--features": "any"}
_CARGO_TARGET_SELECT_BOOL = ("--lib", "--bins", "--examples", "--tests", "--benches",
                             "--all-targets", "--doc")
_CARGO_TARGET_SELECT_VALUE = {"--bin": "any", "--example": "any", "--test": "any",
                              "--bench": "any"}
_CARGO_COMPILE_BOOL = ("-r", "--release", "--keep-going", "--unit-graph", "--timings",
                       "--future-incompat-report")
_CARGO_COMPILE_VALUE = {"-j": "int", "--jobs": "int", "--profile": "any",
                        "--target": "any", "--message-format":
                        frozenset({"human", "short", "json", "json-diagnostic-short",
                                   "json-diagnostic-rendered-ansi",
                                   "json-render-diagnostics"})}
_CARGO_MANIFEST_BOOL = ("--ignore-rust-version",)

HEAD_SPECS["cargo"] = spec(
    bool=_CARGO_ROOT_BOOL,
    value=_CARGO_ROOT_VALUE,
    positional=("max", 1),
    hook="cargo_toolchain",  # a bare leading "+<toolchain>" token, if any
    verbs={
        # -V/--version/--list run standalone with no subcommand at all
        # (`cargo -V`, `cargo --list`) - declared as pseudo-verbs (exact
        # literal match, like any other verb token) since the engine tries
        # a verb match before flag-matching, letting a dash-prefixed
        # literal be recognized as a terminal "verb" here.
        "-V": spec(positional="none"),
        "--version": spec(positional="none"),
        "--list": spec(positional="none"),
        "check": spec(inherit=True, positional="any",
                       bool=_CARGO_PKG_SELECT_BOOL + _CARGO_TARGET_SELECT_BOOL +
                            _CARGO_FEATURE_BOOL + _CARGO_COMPILE_BOOL +
                            _CARGO_MANIFEST_BOOL,
                       value=dict(**_CARGO_PKG_SELECT_VALUE, **_CARGO_TARGET_SELECT_VALUE,
                                  **_CARGO_FEATURE_VALUE, **_CARGO_COMPILE_VALUE)),
        "build": spec(inherit=True, positional="any",
                      bool=_CARGO_PKG_SELECT_BOOL + _CARGO_TARGET_SELECT_BOOL +
                           _CARGO_FEATURE_BOOL + _CARGO_COMPILE_BOOL +
                           _CARGO_MANIFEST_BOOL,
                      value=dict(**_CARGO_PKG_SELECT_VALUE, **_CARGO_TARGET_SELECT_VALUE,
                                 **_CARGO_FEATURE_VALUE, **_CARGO_COMPILE_VALUE)),
        # --lib/--bins/--tests/--all-targets select which targets to
        # build+test; --bin/--test/--target name one of them - direct
        # `cargo test` flags (distinct from the forwarded libtest flags
        # after `--`, which go through `cargo_test_libtest_forward`).
        "test": spec(inherit=True,
                     bool=("--no-run", "--no-fail-fast", "--future-incompat-report") +
                          _CARGO_PKG_SELECT_BOOL + _CARGO_TARGET_SELECT_BOOL +
                          _CARGO_FEATURE_BOOL + _CARGO_COMPILE_BOOL + _CARGO_MANIFEST_BOOL,
                     value=dict({"--message-format":
                                 frozenset({"human", "short", "json",
                                            "json-diagnostic-short",
                                            "json-diagnostic-rendered-ansi",
                                            "json-render-diagnostics"})},
                                **_CARGO_PKG_SELECT_VALUE, **_CARGO_TARGET_SELECT_VALUE,
                                **_CARGO_FEATURE_VALUE, **_CARGO_COMPILE_VALUE),
                     positional="any",
                     after_dashdash=("forward", "cargo_test_libtest_forward")),
        "tree": spec(inherit=True, positional="any",
                     bool=("--no-dedupe", "-d", "--duplicates"),
                     value={"-e": "any", "--edges": "any", "-i": "any", "--invert": "any",
                            "--prune": "any", "--depth": "any", "--prefix":
                            frozenset({"depth", "indent", "none"}),
                            "--charset": frozenset({"utf8", "ascii"}),
                            "-f": "any", "--format": "any",
                            "-p": "any", "--package": "any", "--exclude": "any",
                            "--target": "any", "-F": "any", "--features": "any"},
                     optional={"-i": "any", "--invert": "any"}),
        "clippy": spec(inherit=True, bool=("--all-targets", "--all", "--no-deps"),
                        value={"--explain": "any"},
                        after_dashdash=("forward", "cargo_clippy_forward"),
                        positional="any"),
        "fmt": spec(inherit=True, bool=("--all", "--check", "--version"),
                    value={"-p": "any", "--package": "any", "--manifest-path": "any",
                           "--message-format": frozenset({"short", "json", "human"})},
                    after_dashdash=("forward", "cargo_fmt_forward"),
                    require_any_of=("--check",),
                    positional="none"),
        "metadata": spec(inherit=True, bool=("--no-deps",) + _CARGO_FEATURE_BOOL,
                          value=dict({"--filter-platform": "any",
                                      "--format-version": frozenset({"1"})},
                                     **_CARGO_FEATURE_VALUE),
                          positional="none",
                          require_any_of=("--no-deps",)),
        "package": spec(inherit=True, bool=("-l", "--list"), positional="none",
                         require_any_of=("-l", "--list")),
    },
    require_verb=True,
)


# ---------------------------------------------------------------------
# go test (+ test-binary forward after `-args`). DOC pkg.go.dev/cmd/go
# (go not installed locally - not independently re-verified live this
# session; recommend an owner spot-check with an installed go).
# ---------------------------------------------------------------------
HEAD_SPECS["go"] = spec(verbs={
    "test": spec(
        # go's flag package treats "-x" and "--x" identically (dash-count
        # equivalence, AGENTS.md security-surface note) - both spellings
        # declared explicitly (no abbreviation logic in the engine).
        bool=("-v", "--v", "-short", "--short", "-race", "--race",
              "-cover", "--cover", "-failfast", "--failfast",
              "-benchmem", "--benchmem", "-json", "--json"),
        value={"-run": "any", "--run": "any", "-skip": "any", "--skip": "any",
               "-count": "int", "--count": "int",
               "-parallel": "int", "--parallel": "int",
               "-list": "any", "--list": "any",
               "-timeout": "any", "--timeout": "any",
               "-cpu": "any", "--cpu": "any",
               "-shuffle": "any", "--shuffle": "any",
               "-bench": "any", "--bench": "any",
               "-benchtime": "any", "--benchtime": "any",
               "-covermode": frozenset({"set", "count", "atomic"}),
               "--covermode": frozenset({"set", "count", "atomic"}),
               "-coverpkg": "any", "--coverpkg": "any"},
        positional="any",
        # `-args`/`--args` ends go's own flag space; forwarded content is
        # matched against the test-binary's own `-test.*` namespace
        # (go_test_binary_forward) - this closes `go test ./... -args
        # -test.coverprofile=x` (plan STEP-W5 explicit pin: not in the
        # forward spec's value dict -> rejected) while recovering
        # legitimate forwarded flags (-test.run/-test.v/...) that a
        # blanket "forbid" would also have lost.
        after_dashdash=("forward", "go_test_binary_forward"),
        dashdash_literals=("-args", "--args"),
    ),
}, require_verb=True)


# ---------------------------------------------------------------------
# pip (LIVE `pip3 list/show/freeze --help`, pip 26.0.1, 2026-09-27).
# CORRECTNESS FIX: "pip outdated" is not a real pip subcommand - the real
# facility is `pip list --outdated`/`-o` (old draft bug, removed).
# ---------------------------------------------------------------------
_PIP_GENERAL_BOOL = ("--debug", "--isolated", "--require-virtualenv", "-v", "--verbose",
                     "-V", "--version", "-q", "--quiet", "--no-input",
                     "--disable-pip-version-check", "--no-color")
_PIP_GENERAL_VALUE = {"--python": "any", "--keyring-provider": "any",
                      "--retries": "int", "--timeout": "int",
                      "--use-feature": "any", "--use-deprecated": "any",
                      "--resume-retries": "int"}
# EXCLUDED from general options (not admitted anywhere): --log (writes a
# named file), --cache-dir (writes cache into a user-named dir), --proxy
# (endpoint switch), --trusted-host (disables TLS host verification),
# --cert/--client-cert (credential material paths), --exists-action
# (install-only, n/a).
_PIP_GENERAL_BOOL_SAFE_CACHE = ("--no-cache-dir",)  # disables caching - no write

_PIP_INDEX_BOOL = ("--pre", "--prefer-binary")
_PIP_INDEX_VALUE = {"--no-binary": "any", "--only-binary": "any",
                    "--all-releases": "any", "--only-final": "any"}
# EXCLUDED: -i/--index-url, --extra-index-url, -f/--find-links, --no-index
# (all switch the package-index ENDPOINT).

HEAD_SPECS["pip"] = spec(verbs={
    "list": spec(bool=("-o", "--outdated", "-u", "--uptodate", "-e", "--editable",
                       "-l", "--local", "--user", "--not-required",
                       "--exclude-editable", "--include-editable") +
                      _PIP_GENERAL_BOOL + _PIP_GENERAL_BOOL_SAFE_CACHE + _PIP_INDEX_BOOL,
                 value=dict({"--path": "any", "--format": frozenset({"columns", "freeze", "json"}),
                             "--exclude": "any"}, **_PIP_GENERAL_VALUE, **_PIP_INDEX_VALUE),
                 positional="none"),
    "show": spec(bool=("-f", "--files") + _PIP_GENERAL_BOOL + _PIP_GENERAL_BOOL_SAFE_CACHE,
                 value=_PIP_GENERAL_VALUE,
                 positional="any"),
    "freeze": spec(bool=("-l", "--local", "--user", "--all", "--exclude-editable") +
                        _PIP_GENERAL_BOOL + _PIP_GENERAL_BOOL_SAFE_CACHE,
                   value=dict({"-r": "any", "--requirement": "any",
                               "--path": "any", "--exclude": "any"}, **_PIP_GENERAL_VALUE),
                   positional="none"),
    "check": spec(bool=_PIP_GENERAL_BOOL, value=_PIP_GENERAL_VALUE, positional="none"),
    "inspect": spec(bool=("--local", "--user", "--exclude-editable") +
                         _PIP_GENERAL_BOOL + _PIP_GENERAL_BOOL_SAFE_CACHE,
                     value=dict({"--path": "any"}, **_PIP_GENERAL_VALUE),
                     positional="none"),
    "debug": spec(bool=("--verbose",) + _PIP_GENERAL_BOOL, value=_PIP_GENERAL_VALUE,
                  positional="none"),
    "cache": spec(require_verb=True, verbs={
        "list": spec(bool=_PIP_GENERAL_BOOL, value=_PIP_GENERAL_VALUE, positional="any"),
        "dir": spec(bool=_PIP_GENERAL_BOOL, positional="none"),
        "info": spec(bool=_PIP_GENERAL_BOOL, positional="none"),
        # "remove"/"purge" deliberately absent: delete cache entries.
    }),
    "config": spec(require_verb=True, verbs={
        "list": spec(bool=_PIP_GENERAL_BOOL, positional="none"),
        "get": spec(bool=_PIP_GENERAL_BOOL, positional="any"),
        "debug": spec(bool=_PIP_GENERAL_BOOL, positional="none"),
        # "set"/"unset"/"edit" deliberately absent: write pip.conf.
    }),
}, require_verb=True)


HEAD_SPECS["npm"] = None  # placeholder overwritten immediately below
# npm (DOC docs.npmjs.com/cli/v10/commands/npm-ls; npm not installed
# locally). "ls" is npm's documented alias of "list" (spelling-equivalence
# gap, same class the AGENTS.md security-surface note calls out).
_NPM_LS_BOOL = ("-a", "--all", "-j", "--json", "-l", "--long", "--parseable",
               "-g", "--global", "--link", "--package-lock-only", "-u", "--unicode",
               "--workspaces", "--include-workspace-root", "--install-links")
_NPM_LS_VALUE = {"--depth": "any", "--omit": "any", "--include": "any",
                 "--workspace": "any"}

HEAD_SPECS["npm"] = spec(verbs={
    "list": spec(bool=_NPM_LS_BOOL, value=_NPM_LS_VALUE, positional="any"),
    "ls": spec(bool=_NPM_LS_BOOL, value=_NPM_LS_VALUE, positional="any"),
    "outdated": spec(bool=("-a", "--all", "-j", "--json", "-l", "--long",
                          "--parseable", "-g", "--global"),
                     value={"--workspace": "any"}, positional="any"),
    "view": spec(positional="any"),
    "info": spec(positional="any"),
    "show": spec(positional="any"),
    "whoami": spec(positional="none"),
    "ping": spec(positional="none"),
    "doctor": spec(positional="none"),
    "explain": spec(positional="any"),
    "fund": spec(bool=("--json",), positional="any"),
    "audit": spec(positional="none"),  # bare "npm audit" only; "audit fix" excluded
    "config": spec(require_verb=True, verbs={
        "list": spec(bool=("--json", "-l", "--long"), positional="none"),
        "get": spec(positional="any"),
    }),
}, require_verb=True)

# pnpm (DOC pnpm.io/cli/list; pnpm not installed locally). Same alias gap
# as npm: "pnpm ls" is documented but was missing from the draft.
_PNPM_LIST_BOOL = ("-r", "--recursive", "--json", "--long", "--lockfile-only",
                   "--parseable", "-g", "--global", "-P", "--prod", "-D", "--dev",
                   "--no-optional", "--only-projects", "--exclude-peers")
_PNPM_LIST_VALUE = {"--depth": "any", "--filter": "any", "--find-by": "any"}

HEAD_SPECS["pnpm"] = spec(verbs={
    "list": spec(bool=_PNPM_LIST_BOOL, value=_PNPM_LIST_VALUE, positional="any"),
    "ls": spec(bool=_PNPM_LIST_BOOL, value=_PNPM_LIST_VALUE, positional="any"),
    "outdated": spec(bool=("--long", "--json", "-r", "--recursive"),
                     value={"--filter": "any"}, positional="any"),
    "why": spec(bool=("--json", "-r", "--recursive"), positional="any"),
}, require_verb=True)

# `uv` itself is NOT a HEAD_SPECS entry: `uv run <inner>` is a run-prefix
# (REQ-07) - the engine unwraps it via cli_families.run_prefix_split
# (LIVE-verified against `uv run --help`, uv 0.7.2, 2026-09-27 - the
# RUN_PREFIXES["uv"] table already matches the installed binary's full
# flag surface, no changes needed) and then matches the INNER command
# against ITS OWN entry here; a `uv` entry would be unreachable dead data.


# ---------------------------------------------------------------------
# Mobile toolchains (TK-42). LIVE `flutter --help`/`analyze --help`/
# `test --help`, `dart analyze --help`, `swift build/test --help`,
# `xcrun --help` (2026-09-27); `flutter pub outdated`, `dart test`'s own
# flags, `swift test`'s selection flags, swiftlint, swiftformat, xcodebuild
# and xcrun-simctl could not run live (no pubspec/package/full-Xcode
# context) - DOC/TRAIN, flagged per-flag in the research proposal.
# ---------------------------------------------------------------------
HEAD_SPECS["flutter"] = spec(verbs={
    "doctor": spec(positional="none"),
    "analyze": spec(bool=("--current-package", "--no-current-package",
                          "--suggestions", "--no-suggestions", "--no-pub",
                          "--congratulate", "--no-congratulate",
                          "--preamble", "--no-preamble",
                          "--fatal-infos", "--no-fatal-infos",
                          "--fatal-warnings", "--no-fatal-warnings"),
                    positional="any"),
    "test": spec(value={"--plain-name": "any", "--name": "any", "-t": "any", "--tags": "any",
                        "-x": "any", "--exclude-tags": "any",
                        "-r": frozenset({"compact", "expanded", "failures-only",
                                          "github", "json", "silent"}),
                        "--reporter": frozenset({"compact", "expanded", "failures-only",
                                                   "github", "json", "silent"}),
                        "--timeout": "any",
                        "-j": "int", "--concurrency": "int",
                        "--test-randomize-ordering-seed": "any",
                        "--total-shards": "int", "--shard-index": "int"},
                 bool=("--fail-fast", "--no-fail-fast", "--run-skipped",
                      "--coverage", "--merge-coverage", "--branch-coverage",
                      "--ignore-timeouts", "--wasm",
                      "--track-widget-creation", "--no-track-widget-creation",
                      "--test-assets", "--no-test-assets"),
                 positional="any"),
    "pub": spec(verbs={
        "outdated": spec(bool=("--json", "--dependency-overrides",
                               "--no-dependency-overrides", "--dev-dependencies",
                               "--no-dev-dependencies", "--prereleases",
                               "--no-prereleases", "--show-all", "--no-show-all",
                               "--transitive", "--no-transitive", "--up-to-date"),
                         value={"--mode": "any"}, positional="any"),
        "deps": spec(bool=("--dev", "--no-dev", "--executables", "--json"),
                     value={"-s": frozenset({"compact", "tree", "list"}),
                            "--style": frozenset({"compact", "tree", "list"}),
                            "-C": "any", "--directory": "any"},
                     positional="any"),
    }, require_verb=True),
}, require_verb=True)
HEAD_SPECS["dart"] = spec(verbs={
    "analyze": spec(bool=("--fatal-infos", "--fatal-warnings", "--no-fatal-warnings"),
                     positional="any"),
    "test": spec(bool=("--fail-fast", "--no-fail-fast", "--run-skipped",
                       "--chain-stack-traces"),
                 value={"-n": "any", "--name": "any", "-N": "any", "--plain-name": "any",
                        "-t": "any", "--tags": "any", "-x": "any", "--exclude-tags": "any",
                        "-j": "int", "--concurrency": "int",
                        "-r": frozenset({"compact", "expanded", "failures-only",
                                          "github", "json", "silent"}),
                        "--reporter": frozenset({"compact", "expanded", "failures-only",
                                                   "github", "json", "silent"}),
                        "--timeout": "any", "--test-randomize-ordering-seed": "any",
                        "--retry": "int", "-p": "any", "--platform": "any",
                        "--compiler": "any", "--preset": "any"},
                 positional="any"),
                 # EXCLUDED: --coverage=<dir> (unlike flutter's boolean
                 # --coverage, dart test's takes a value and writes JSON
                 # coverage data to a user-named dir - a real per-head
                 # divergence, do not copy flutter's ADMIT here);
                 # --file-reporter (user-named file); --debug/
                 # --pause-after-load (wait for a debugger - hang class).
}, require_verb=True)
_SWIFT_BUILD_TEST_SHARED_BOOL = (
    "-v", "--verbose", "--very-verbose", "--vv", "-q", "--quiet",
    "--color-diagnostics", "--no-color-diagnostics",
    "--enable-dependency-cache", "--disable-dependency-cache",
    "--enable-build-manifest-caching", "--disable-build-manifest-caching",
    "--enable-experimental-prebuilts", "--disable-experimental-prebuilts",
    "--enable-prefetching", "--disable-prefetching",
    "--force-resolved-versions", "--disable-automatic-resolution",
    "--only-use-versions-from-resolved-file", "--skip-update",
    "--disable-scm-to-registry-transformation", "--use-registry-identity-for-scm",
    "--replace-scm-with-registry",
    "--enable-all-traits", "--disable-default-traits",
    "--enable-dead-strip", "--disable-dead-strip", "--disable-local-rpath",
)
_SWIFT_BUILD_TEST_SHARED_VALUE = {
    "--package-path": "any", "--scratch-path": "any",
    "-c": frozenset({"debug", "release"}), "--configuration": frozenset({"debug", "release"}),
    "--triple": "any", "--sdk": "any", "--swift-sdk": "any",
    "--sanitize": frozenset({"address", "thread", "undefined", "scudo", "fuzzer"}),
    "--build-system": frozenset({"native", "swiftbuild", "xcode"}),
    "-debug-info-format": frozenset({"dwarf", "codeview", "none"}),
    "-j": "int", "--jobs": "int", "--traits": "any",
    "--manifest-cache": frozenset({"shared", "local", "none"}),
}
# EXCLUDED (all swift heads): -Xcc/-Xswiftc/-Xlinker/-Xcxx (unbounded
# compiler/linker passthrough); --toolchain/--toolset (loads an alternate
# named compiler toolchain); --disable-sandbox (security downgrade);
# --netrc*/--keychain* (credential-store config);
# --resolver-fingerprint-checking/--resolver-signing-entity-checking/
# --enable-signature-validation/--disable-signature-validation
# (supply-chain security posture); --default-registry-url (registry
# endpoint switch); --cache-path/--config-path/--security-path/
# --swift-sdks-path/--pkg-config-path (path redirects, doubt->exclude).

HEAD_SPECS["swift"] = spec(verbs={
    "build": spec(bool=_SWIFT_BUILD_TEST_SHARED_BOOL,
                  value=dict(_SWIFT_BUILD_TEST_SHARED_VALUE, **{"--product": "any"}),
                  positional="any"),
    "test": spec(bool=_SWIFT_BUILD_TEST_SHARED_BOOL + ("--parallel", "--no-parallel",
                                                        "-l", "--list-tests",
                                                        "--enable-code-coverage",
                                                        "--show-codecov-path"),
                 value=dict(_SWIFT_BUILD_TEST_SHARED_VALUE,
                            **{"--filter": "any", "--skip": "any", "--num-workers": "int"}),
                 positional="any"),
}, require_verb=True)
# swiftlint: doc fetches this session returned only generic usage text
# (TRAIN - well-established, stable CLI; recommend an owner spot-check
# with `swiftlint lint --help` if available).
HEAD_SPECS["swiftlint"] = spec(verbs={
    "lint": spec(bool=("--strict", "--quiet", "--no-cache", "--force-exclude",
                       "--lenient", "--use-alternative-excluding",
                       "--use-script-input-files", "--use-script-input-file-lists",
                       "--enable-all-rules", "--progress", "--compare-baselines"),
                 value={"--config": "any",
                        "--reporter": frozenset({"xcode", "json", "csv", "checkstyle",
                                                   "codeclimate", "junit", "html", "emoji",
                                                   "sonarqube", "markdown",
                                                   "github-actions-logging", "summary"}),
                        "--baseline": "any"},
                 positional="any", forbid_write_token=True),
    "version": spec(positional="none"),
    "rules": spec(positional="any"),
}, require_verb=True)
# swiftformat: DOC (github.com/nicklockwood/SwiftFormat README, partial -
# ~80 per-rule formatting flags not enumerable from what was fetched;
# omitting them is a compression loss, not a security gap).
HEAD_SPECS["swiftformat"] = spec(
    bool=("--lint", "--dryrun", "--dry-run", "--quiet", "--verbose", "--lenient",
         "--options", "--rules"),
    value={"--config": "any", "--swiftversion": "any", "--languagemode": "any",
          "--exclude": "any", "--unexclude": "any", "--stdinpath": "any",
          "--minversion": "any",
          "--cache": frozenset({"clear", "ignore"})},  # NOT "any" - excludes the
          # user-named-path form of --cache, admits only the two safe literal modes
    positional="any",
    require_any_of=("--lint", "--dryrun", "--dry-run"),
    forbid_write_token=True,
)
# xcodebuild: not installed (CLT-only, no full Xcode) - TRAIN.
# NAMED OWNER-DECISION (behaviour-parity, left AS TODAY): research this
# pass found that `require_any_of` including `-scheme`/`-destination` is
# unsafe on its own - `xcodebuild -scheme Foo -destination X` with NEITHER
# `-list`/`-showsdks`/`-showBuildSettings` present actually DEFAULTS TO
# THE `build` ACTION (compiles and writes build products), so the gate as
# written can auto-approve a real build as if it were observational. This
# characteristic already existed in the OLD rewriter's `_xcodebuild_ok`
# (`"-scheme" in rest or "-destination" in rest` -> True) - it is NOT a
# regression introduced by this pass. Per explicit instruction this stays
# UNCHANGED pending an owner decision (narrowing `require_any_of` to drop
# `-scheme`/`-destination` is the recommended fix once decided).
HEAD_SPECS["xcodebuild"] = spec(
    bool=("-list", "-showsdks", "-showBuildSettings", "-json", "-quiet", "-verbose"),
    value={"-project": "any", "-workspace": "any", "-scheme": "any",
          "-destination": "any", "-configuration": "any", "-sdk": "any"},
    positional="any",
    require_any_of=("-list", "-showsdks", "-showBuildSettings",
                     "-scheme", "-destination"),
)
# `xcrun` itself is not an entry (same run-prefix reasoning as `uv`
# above): `xcrun simctl <verb>` unwraps to the inner head "simctl", which
# IS the entry actually matched. LIVE `xcrun --help` confirmed
# cli_families.RUN_PREFIXES["xcrun"] already matches the installed binary
# exactly (2026-09-27, no changes needed); `simctl` itself isn't
# installed (needs full Xcode) - its own flags are TRAIN.
HEAD_SPECS["simctl"] = spec(verbs={"list": spec(bool=("-j", "--json"), positional="any")},
                             require_verb=True)
# pod (CocoaPods; DOC guides.cocoapods.org/terminal/commands.html).
HEAD_SPECS["pod"] = spec(verbs={
    "outdated": spec(bool=("--ignore-prerelease", "--no-repo-update",
                           "--allow-root", "--silent", "--version", "--verbose", "--no-ansi"),
                     value={"--project-directory": "any"}, positional="any"),
    # NOTE: "--update" is deliberately NOT admitted on `list` - it
    # triggers a `pod repo update` first (writes/fetches into the local
    # spec-repo cache); the research proposal's own flag table said
    # EXCLUDE for exactly this reason but its pasted code block
    # contradictorily included it in `list`'s bool tuple - dropped here
    # (confirmed by a "must NOT rewrite" pin: `pod list --update`).
    "list": spec(bool=("--stats",
                       "--allow-root", "--silent", "--version", "--verbose", "--no-ansi"),
                 positional="any"),
    "search": spec(bool=("--regex", "--simple", "--stats", "--ios", "--osx",
                        "--watchos", "--visionos", "--tvos", "--no-pager",
                        "--allow-root", "--silent", "--version", "--verbose", "--no-ansi"),
                   positional="any"),
    "env": spec(bool=("--allow-root", "--silent", "--version", "--verbose", "--no-ansi"),
                positional="none"),
    "spec": spec(require_verb=True, verbs={
        "which": spec(bool=("--regex", "--show-all"), value={"--version": "any"},
                       positional="any"),
        "cat": spec(bool=("--regex", "--show-all"), value={"--version": "any"},
                     positional="any"),
    }),
}, require_verb=True)


# ---------------------------------------------------------------------
# ./gradlew - flags come straight from cli_families.GRADLE_* (already an
# exhaustive dated table) plus a small local extras tuple confirmed via
# Gradle's own CLI reference (docs.gradle.org, fetched 2026-09-27) - kept
# here rather than editing cli_families.py per the plan's Scope section
# (G4 = git exec-flags table only). Per-positional TASK classification
# needs a hook (REQ-06: cli_families.gradle_task_class, reused verbatim).
# ---------------------------------------------------------------------
_GRADLEW_EXTRA_BOOL = (
    "-V", "--show-version",   # prints version and continues (distinct from -v/--version)
    "--status",                # lists running/stopped daemons - RO
    "--task-graph",            # prints task dependency graph, actions disabled - RO
    "--problems-report", "--no-problems-report",  # toggle a fixed-path report
    "--isolated-projects", "--no-isolated-projects",
    "--non-interactive",
)
# Deliberately NOT added (confirmed to WRITE local files/state):
#   --refresh-keys, --export-keys (write/refresh the local verification
#   keyring); --stop, --foreground, --write-locks, --update-locks,
#   --write-verification-metadata (already excluded - endorsed, unchanged).
# EXCLUDED from cli_families.GRADLE_VALUE_FLAGS (finding A, wave
# 2026-09-27, confirmed live: `./gradlew --init-script evil.gradle build`
# was admitted): `-I`/`--init-script <FILE>` makes Gradle EXECUTE the named
# file as a Groovy/Kotlin init script before the build starts - unlike a
# declarative config-file-path flag, the file's entire content runs as
# code (can itself `exec` arbitrary commands). GRADLE_VALUE_FLAGS is
# shared with the security gate's task scanner (t6_tools.py, needs the
# full table to correctly skip flag VALUES while looking for task
# tokens) so it is not edited there; only the rewriter's own admission
# excludes these two spellings.
_GRADLEW_VALUE_EXCLUDED = frozenset({"-I", "--init-script"})
HEAD_SPECS["./gradlew"] = spec(
    bool=cli_families.GRADLE_BOOL_FLAGS + _GRADLEW_EXTRA_BOOL,
    value=dict({f: "any" for f in cli_families.GRADLE_VALUE_FLAGS
                if f not in _GRADLEW_VALUE_EXCLUDED},
               # --configuration <name>: selects which dependency
               # configuration `dependencies`/`dependencyInsight` report
               # on - RO. Not in cli_families.GRADLE_VALUE_FLAGS (that
               # table is scoped to git-only edits per plan §Scope, G4);
               # added locally instead, same pattern as _GRADLEW_EXTRA_BOOL.
               **{"--configuration": "any"}),
    positional="any",
    hook="gradle_task",
)


# ---------------------------------------------------------------------
# SQL CLIs (psql/sqlite3/duckdb) - flag grammar closed from the exact
# corpus' positive spellings plus DOC/LIVE research; `sql_payload` hook
# (REQ-06) reuses `sql_verbs.sql_payloads`/`classify_payload` verbatim for
# the actual RO/dangerous classification of the SQL text itself (never
# duplicated). File-based SQL (`-f`/`--file`/`-init`) and admin/credential
# flags are closed simply by never declaring them.
# ---------------------------------------------------------------------
# psql: DOC postgresql.org/docs/current/app-psql.html, full OPTIONS
# section. SECURITY FINDING (payload-smuggling): `-v NAME=VALUE`/`--set`/
# `--variable` sets a session variable psql substitutes at RUNTIME
# wherever `:NAME` appears in later `-c`/`-f` text - the literal string
# the `sql_payload` hook classifies is not necessarily what psql actually
# executes if `-v` is also present. `-v`/`--set`/`--variable` stay
# EXCLUDED (never declared) until the hook is taught to also inspect `-v`
# assignments. `-f`/`--file` stays excluded too (file-content
# classification is out of scope, same G1/E-010 `grep -f` precedent).
HEAD_SPECS["psql"] = spec(
    bool=("-t", "--tuples-only", "-A", "--no-align", "-q", "--quiet",
          "-X", "--no-psqlrc", "-H", "--html", "--csv", "-x", "--expanded",
          "-z", "--field-separator-zero", "-0", "--record-separator-zero",
          "-a", "--echo-all", "-b", "--echo-errors", "-e", "--echo-queries",
          "-E", "--echo-hidden", "-n", "--no-readline", "-l", "--list",
          "-V", "--version", "-s", "--single-step", "-S", "--single-line",
          "-1", "--single-transaction", "-w", "--no-password", "-W", "--password"),
    value={"-c": "any", "--command": "any", "-d": "any", "--dbname": "any",
           "-h": "any", "--host": "any", "-p": "any", "--port": "any",
           "-U": "any", "--username": "any",
           "-P": "any", "--pset": "any", "-F": "any", "--field-separator": "any",
           "-R": "any", "--record-separator": "any", "-T": "any", "--table-attr": "any"},
    optional={"-?": "any", "--help": "any"},
    cluster=True,  # psql admits combined short bools, e.g. `-At`, `-qtA`
    positional="any",
    hook="sql_payload",
)
# sqlite3: LIVE `/usr/bin/sqlite3 --help`/`-version` (3.43.2), 2026-09-27.
# `-lookaside SIZE N`/`-pagecache SIZE N` consume TWO following tokens
# each - the grammar's value/optional primitives only ever consume one,
# so these are excluded as a genuine grammar-expressiveness gap (not a
# judgment call). `-key/-hexkey/-textkey` carry encryption key material
# (credential class). `-safe`/`-nofollow` strictly strengthen the security
# posture (admitted); `-nonce`/`-unsafe-testing` exist specifically to
# escape/weaken `-safe` mode (excluded). `-help` is single-dash on this
# binary (dash-count correction from the earlier draft's `--help`).
HEAD_SPECS["sqlite3"] = spec(
    bool=("-json", "-readonly", "-list", "-csv", "-line", "-header",
          "-noheader", "-batch", "-bail", "-ascii", "-box", "-column",
          "-html", "-markdown", "-quote", "-table", "-tabs", "-echo",
          "-stats", "-memtrace", "-pcachetrace", "-safe", "-nofollow",
          "-append", "-version", "-help"),
    value={"-separator": "any", "-cmd": "any", "--cmd": "any",
          "-newline": "any", "-nullvalue": "any",
          "-vfs": frozenset({"unix", "unix-dotfile", "unix-excl", "unix-none",
                              "unix-namedsem"})},
    positional=("max", 2),
    after_dashdash="positional",
    hook="sql_payload",
)
# EXCLUDED, not added (sqlite3): -lookaside/-pagecache (2-value flags,
# grammar cannot express); -key/-hexkey/-textkey (credential material);
# -nonce (escapes -safe); -unsafe-testing (endorsed, unchanged);
# -interactive (hang risk without a TTY); -deserialize (doubt);
# -init/-A (already excluded - payload/archive-write, endorsed).

# duckdb: DOC (duckdb's shell is an explicit fork of sqlite3's shell.c -
# moderate confidence, recommend an owner spot-check with a locally
# installed `duckdb --help`). `-unsafe` is MORE severe than sqlite3's
# `-unsafe-testing` - it explicitly enables loading UNSIGNED extension
# code (definite exclude).
HEAD_SPECS["duckdb"] = spec(
    bool=("-json", "-readonly", "-list", "-line", "-csv", "-header",
          "-noheader", "-column", "-ascii", "-html", "-markdown",
          "-bail", "-echo", "-batch", "-safe", "-nofollow", "-no-stdin"),
    value={"-c": "any", "-s": "any", "-cmd": "any", "--cmd": "any",
          "-newline": "any", "-separator": "any", "-nullvalue": "any"},
    positional=("max", 2),
    after_dashdash="positional",
    hook="sql_payload",
)
# EXCLUDED, not added (duckdb): -init (file-content classification out of
# scope, same as sqlite3); -unsafe (unsigned extensions - security
# weakening); -new (doubt, not confidently understood this session).


# dbt: DOC docs.getdbt.com/reference/global-configs/command-line-options
# (partial) + TRAIN (dbt-core ~1.8/1.9-era, well-known; recommend an owner
# spot-check against `dbt --help`/`dbt test --help`).
#
# OWNER DECISION (resolved): `run`/`build` are REMOVED from the admitted
# verb set - they CREATE/REPLACE objects in the connected data warehouse
# (data-integrity criterion), a materially different risk than a local
# filesystem write, unlike `test` (read-only assertions by design),
# `list`/`ls` (pure DAG/selection metadata), and `compile` (renders SQL
# without executing it against the warehouse). This is an approved loss
# relative to the old fully-open `run`/`build --select ...` admission -
# the exact-corpus and typical-usage fixture rows for `dbt run`/`dbt
# build` are updated to the expected `null` in the same commit.
_DBT_SHARED_BOOL = ("--fail-fast", "-x", "--defer", "--no-defer", "--favor-state",
                    "--no-favor-state", "-q", "--quiet", "--no-print", "--print",
                    "--use-colors", "--no-use-colors", "--partial-parse",
                    "--no-partial-parse", "--populate-cache", "--no-populate-cache",
                    "--version-check", "--no-version-check",
                    "--send-anonymous-usage-stats", "--no-send-anonymous-usage-stats",
                    "--write-json", "--no-write-json", "--empty")
_DBT_SHARED_VALUE = {"--select": "any", "-s": "any", "--models": "any", "-m": "any",
                    "--exclude": "any", "--selector": "any", "--state": "any",
                    "--threads": "int",
                    "--log-level": frozenset({"debug", "info", "warn", "error", "none"}),
                    "--log-format": frozenset({"text", "json", "debug"}),
                    "--indirect-selection": frozenset({"eager", "cautious",
                                                         "buildable", "empty"})}
# NOTE on --vars: deliberately EXCLUDED (not in _DBT_SHARED_VALUE) - can
# inject arbitrary Jinja values consumed by custom macros; doubt->exclude.
# -t/--target, --profile/--profiles-dir: EXCLUDED (target/credential-
# switch class, brief's explicit rule, no dbt exception). --target-path/
# --log-path: EXCLUDED (redirect output to a user-named directory).

# list/ls-only extras: pure output-shaping/filtering of the metadata
# listing itself, no warehouse connection or execution either way.
_DBT_LIST_VALUE = dict(_DBT_SHARED_VALUE, **{
    "--output": frozenset({"name", "path", "selector", "json"}),
    "--resource-type": "any",
})

HEAD_SPECS["dbt"] = spec(verbs={
    # "run"/"build" deliberately NOT admitted - see owner-decision note above.
    "test": spec(bool=_DBT_SHARED_BOOL, value=_DBT_SHARED_VALUE, positional="any"),
    "compile": spec(bool=_DBT_SHARED_BOOL, value=_DBT_SHARED_VALUE, positional="any"),
    "list": spec(bool=_DBT_SHARED_BOOL, value=_DBT_LIST_VALUE, positional="any"),
    "ls": spec(bool=_DBT_SHARED_BOOL, value=_DBT_LIST_VALUE, positional="any"),
}, require_verb=True)


# ---------------------------------------------------------------------
# terraform (hand-authored, not family-derived - the family loop skips
# any head already in HEAD_SPECS; cli_families.FAMILIES["terraform"]'s own
# ro_verbs list is therefore unused/dead for terraform specifically, a
# pre-existing situation matching plan doc's own E-008 observation, not
# introduced here). DOC developer.hashicorp.com/terraform/cli/commands
# (plan/show/validate fetched this session; graph/validate's -no-tests/
# -test-directory and version/graph's own flags are TRAIN, flagged below -
# terraform not installed locally, recommend an owner spot-check).
# ---------------------------------------------------------------------
_TF_VAR_VALUE = {"-var": "any", "-var-file": "any"}

HEAD_SPECS["terraform"] = spec(verbs={
    "plan": spec(bool=("-input=false", "-no-color", "-compact-warnings",
                       "-detailed-exitcode", "-json", "-destroy", "-refresh-only"),
                 value=dict(_TF_VAR_VALUE, **{
                     "-refresh": frozenset({"true", "false"}),
                     "-replace": "any", "-target": "any",
                     "-parallelism": "int", "-lock-timeout": "any",
                     "-lock": frozenset({"true", "false"})}),
                 positional="any"),
                 # EXCLUDED: -out=FILENAME (writes a plan file a later
                 # apply can consume without re-showing the diff, already
                 # an ask_spec too); -generate-config-out (writes HCL to a
                 # user-named path); -invoke=action... (doubt, unverified
                 # newer HCL "actions" feature).
    "validate": spec(bool=("-json", "-no-color", "-no-tests"),  # -no-tests: TRAIN
                     value=dict(_TF_VAR_VALUE, **{"-test-directory": "any"}),  # TRAIN
                     positional="any"),
    "show": spec(bool=("-json", "-no-color"), positional="any"),
    "version": spec(bool=("-json",), positional="none"),  # TRAIN, unverified
    "graph": spec(bool=("-draw-cycles", "-no-color"),  # TRAIN, unverified
                  value={"-type": frozenset({"plan", "plan-refresh-only",
                                              "plan-destroy", "apply"}),
                         "-plan": "any"},
                  positional="any"),
    "output": spec(bool=("-json", "-raw", "-no-color"),  # verb addition, TRAIN
                   value={"-state": "any"}, positional="any"),
}, require_verb=True)


# =======================================================================
# Cloud/pflag families (docker TK-41, kubectl/helm TK-40, bq/terraform/
# redis-cli TK-43, gh TK-55 [hand-authored above], vercel/netlify/railway/
# wrangler/supabase/flyctl/gcloud wave-1): derived from `cli_families.
# FAMILIES` (already a dated, docs-cited table) plus FAMILY_EXTRAS -
# additional bool/value flags confirmed either by a live `--help` pull
# this task/a follow-up research pass (docker, kubectl - re-checked
# 2026-09-27) or by official docs (DOC, cited per head) / well-established
# stable-CLI knowledge (TRAIN, flagged low-confidence). A family's
# ro_verbs sequences are reused as this head's verb paths.
# =======================================================================
FAMILY_EXTRAS = {
    # docker: LIVE `docker ps/images/logs/inspect/system df/stats --help`
    # + `docker compose ps/logs --help`, 2026-09-27. `-f` stays bool-only
    # (docker logs/compose logs `--follow`) - `docker ps`/`images` have a
    # SEPARATE `-f`/`--filter` that takes a value; only the unambiguous
    # long spelling `--filter` is added as a value flag to avoid making
    # that short-flag ambiguity worse. `-f`/`--follow`'s safety in
    # practice depends on `hang_policy._is_docker` independently refusing
    # to wrap streaming forms by verb - not reviewed this session,
    # recommend the owner confirm coverage of `logs -f`/`compose logs -f`/
    # `compose up` (no -d)/`attach`/bare `stats`.
    "docker": {
        "bool": ("-a", "--all", "-q", "--quiet", "-l", "--latest", "-s",
                 "--size", "--no-trunc", "--digests", "--details",
                 "-t", "--timestamps", "--tree", "-f", "--follow",
                 "-v", "--verbose",
                 "--dry-run", "--orphans", "--services", "--no-color", "--no-log-prefix"),
        "value": {"-n": "any", "--last": "any", "--tail": "any",
                  "--since": "any", "--until": "any",
                  "--format": "any", "--type": "any", "--filter": "any",
                  "--status": "any", "--index": "any"},
    },
    # kubectl: LIVE `kubectl get/describe/top pod/events/logs --help` +
    # `kubectl options`, 2026-09-27. SECURITY: `--raw <URI>` issues an
    # arbitrary raw HTTP request to the API server bypassing verb
    # semantics entirely - never added. Identity-impersonation
    # (--as/--as-group/--as-uid) and raw-credential flags (--password/
    # --token/--user/--username/--client-certificate/--client-key/
    # --certificate-authority/--server) plus --insecure-skip-tls-verify
    # are likewise never added (none in the owner's existing
    # -n/--namespace/--context/--cluster/--kubeconfig exception list).
    # --tail/--since/--since-time for `kubectl logs` were previously
    # admitted nowhere - fixed below.
    "kubectl": {
        "bool": ("-w", "--watch", "-R", "--recursive", "-p", "--previous",
                 "--show-kind", "--no-headers", "--ignore-not-found",
                 "--allow-missing-template-keys", "--server-print",
                 "--output-watch-events", "--containers", "--show-swap", "--sum",
                 "--use-protocol-buffers", "--all-containers", "--all-pods",
                 "--ignore-errors", "--prefix", "--timestamps",
                 "--disable-compression", "--warnings-as-errors",
                 "--match-server-version"),
        "value": {"-o": "any", "--output": "any", "-l": "any",
                  "--selector": "any", "-f": "any", "--filename": "any",
                  "-k": "any", "--kustomize": "any",
                  "-L": "any", "--label-columns": "any",
                  "-c": "any", "-v": "any",
                  "--tail": "int", "--since": "any", "--since-time": "any",
                  "--field-selector": "any", "--chunk-size": "int",
                  "--sort-by": "any", "--limit-bytes": "int",
                  "--max-log-requests": "int", "--pod-running-timeout": "any",
                  "--subresource": "any", "--for": "any", "--types": "any",
                  "--request-timeout": "any", "--vmodule": "any",
                  "--log-flush-frequency": "any",
                  "--profile": frozenset({"none", "cpu", "heap", "goroutine",
                                           "threadcreate", "block", "mutex"})},
    },
    # EXCLUDED, never added (kubectl): --raw (arbitrary raw API request);
    # --as/--as-group/--as-uid (identity impersonation); --password/
    # --token/--user/--username/--client-certificate/--client-key/
    # --certificate-authority/--server/--tls-server-name (credential/
    # endpoint switch - "--tls-server-name" was in the proposal's own
    # value dict, contradicting its OWN exclusion table and the pre-
    # existing _DENIED_WRITE_FLAGS["kubectl"]["eq"] entry it replaces;
    # dropped, REQ-05 replay caught it as a new admission); --insecure-
    # skip-tls-verify(-backend) (security downgrade); --profile-output
    # (writes a pprof file to a user-named path); --cache-dir (writes
    # kubeconfig cache to a user-named dir).
    #
    # helm: DOC helm.sh/docs/helm/helm_list (comprehensive for `list`
    # only; template/show/status/history/get-metadata are TRAIN, low
    # confidence - doc fetch returned no content for those pages).
    "helm": {
        "bool": ("-A", "--all-namespaces", "-d", "--date", "--deployed", "--failed",
                 "--pending", "--superseded", "--uninstalled", "--uninstalling",
                 "--no-headers", "-r", "--reverse", "-q", "--short",
                 "--validate", "--is-upgrade"),
        "value": {"--output": "any", "-o": "any",  # -o is helm's own short alias
                  "-f": "any", "--filter": "any", "-m": "any", "--max": "any",
                  "--offset": "any", "-l": "any", "--selector": "any",
                  "--time-format": "any",
                  "--revision": "any", "--show-only": "any"},
    },
    # bq: doc fetch failed both times (navigational content only) - TRAIN
    # only, low confidence throughout; recommend an owner follow-up with
    # `bq --help`/`bq help global_flags` before relying on this further.
    "bq": {
        "bool": ("--headless", "--synchronous_mode", "--nosynchronous_mode", "--quiet"),
        "value": {},
    },
    # EXCLUDED, not added (bq): --format (as a real 2-token value flag -
    # bq's own ro_verbs has single-token paths directly off root, so a new
    # root-level value flag creates interposition old never had; REQ-05
    # replay caught `bq --format json ls` as a new admission - the
    # existing "--format=json"/"--format=prettyjson" GLUED bool literals,
    # already present via FAMILIES global_flags, are unaffected and stay);
    # --project_id/--dataset_id (target-switch class); --apilog (writes an
    # API call log to a user-named path); --job_id (doubt, low confidence).
    #
    # gcloud: DOC docs.cloud.google.com/sdk/gcloud/reference, global flags
    # section, fetched 2026-09-27.
    "gcloud": {
        "bool": ("--log-http", "--user-output-enabled"),
        "value": {"--format": "any", "--flatten": "any", "--filter": "any",
                  "--limit": "int", "--sort-by": "any", "--page-size": "int",
                  "--verbosity": frozenset({"debug", "info", "warning", "error",
                                              "critical", "none"}),
                  "--trace-token": "any"},
    },
    # EXCLUDED, not added (gcloud): --account/--project/--billing-project/
    # --configuration/--access-token-file/--impersonate-service-account
    # (target/credential-switch class); --flags-file (loads an entire
    # alternate flag set from a user-named file - the classifier can't
    # inspect its contents, same payload-smuggling caution as psql's -v).
    #
    # vercel: DOC vercel.com/docs/cli/global-options, fetched in full.
    "vercel": {
        "bool": ("-h", "--help", "-v", "--version"),
        "value": {},
    },
    # EXCLUDED, not added (vercel): --cwd (a genuinely safe root-level
    # value flag by itself, but vercel's ro_verbs are single-token paths
    # directly off root - declaring it interposes before the verb in a
    # way old's FAMILIES table never allowed (vercel had no value_flags at
    # all); REQ-05 replay caught `vercel --cwd app list` as a new
    # admission - loss-list candidate for a follow-up owner sign-off, not
    # applied here); --scope/-S, --token/-t, --team/-T, --project (target/
    # credential/project-switch class); --global-config/-Q, --local-
    # config/-A (alternate config file, credential-adjacent).
    #
    # netlify: thin DOC (only the `status` command's own flags page
    # returned content, no global-options page) - low-to-moderate
    # confidence, recommend a follow-up fetch before relying heavily.
    "netlify": {
        "bool": ("--json", "--verbose", "--debug"),
        "value": {},
    },
    # EXCLUDED, not added (netlify): --auth <token> (credential material
    # on the command line).
    #
    # railway: thin DOC (generic global-options table only, no per-command
    # flags for whoami/status/list) - low confidence.
    "railway": {
        "bool": ("--json", "-y", "--yes"),
        "value": {},
    },
    # EXCLUDED, not added (railway): -s/--service, -e/--environment
    # (target/environment-switch class).
    #
    # wrangler: both doc fetches this session returned only navigational
    # content, no substantive flag reference. Per "doubt -> don't
    # include": no additions - the existing empty entry is the correct
    # conservative outcome. Recommend a follow-up with wrangler installed
    # locally or a more specific doc URL before adding anything.
    "wrangler": {"bool": (), "value": {}},
    # supabase: DOC supabase.com/docs/reference/cli/supabase-status,
    # fetched in full (confirms both global flags and that `projects list`
    # has no command-specific flags beyond the globals).
    "supabase": {
        "bool": (),
        "value": {"--output": frozenset({"env", "pretty", "json", "toml", "yaml"}),
                  "-o": frozenset({"env", "pretty", "json", "toml", "yaml"}),
                  "--workdir": "any"},
    },
    # EXCLUDED, not added (supabase): --profile (named API profile/
    # credentials - credential-switch class); --network-id, --agent,
    # --dns-resolver (doubt, low confidence/relevance).
    #
    # flyctl: not installed, no successful doc fetch this session for
    # flyctl specifics - TRAIN only, low confidence. No additions
    # proposed; the existing empty entry is the correct conservative
    # outcome given no verifiable source. (Owner exclusions to apply if
    # later independently confirmed: -a/--app target-app-switch,
    # --access-token credential, --org target-org-switch.)
    "flyctl": {"bool": (), "value": {}},
    "terraform": {"bool": (), "value": {}},
    # redis-cli: DOC redis.io/docs/latest/develop/tools/cli/, fetched in
    # full including the complete Usage: options reference. SECURITY:
    # -a/--pass/--user put credential material directly on the command
    # line (never added; REDISCLI_AUTH is the documented alternative).
    # -r/--repeat's sentinel value -1 means "repeat forever" - the "int"
    # value-domain has no way to carve out "any int except -1", so
    # -r/--repeat is excluded entirely (doubt->exclude, "streams forever"
    # class). Every "special mode" flag (--scan/--bigkeys/--memkeys/
    # --hotkeys/--keystats/--stat/--latency*/--cluster/--eval/--ldb*/
    # --pipe*/--rdb/--functions-rdb/--replica/--lru-test/
    # --intrinsic-latency) is likewise excluded - none participate in the
    # plain EXISTS/TTL/TYPE/SCAN/DBSIZE-style ro_verbs pathway this family
    # already admits, and since flags are checked against the whole tail
    # regardless of which verb is present, admitting any of them risks
    # matching an entirely different, non-RO invocation shape.
    "redis-cli": {
        "bool": ("--no-raw", "--raw", "-3", "-2", "--csv", "-4", "-6",
                 "--no-auth-warning", "--quoted-input", "--quoted-json", "-e",
                 "--verbose"),
        "value": {"-t": "any", "--show-pushes": frozenset({"yes", "no"}),
                  "-d": "any", "-D": "any", "--name": "any"},
    },
}


def _verb_tree(ro_verbs, family_bool=(), family_value=None):
    """Builds a nested verbs dict from FAMILIES-style flat tuples
    (`(("compose", "ps"), ("compose", "logs"), ("ps",))`).

    A node reached by a COMPLETE ro_verbs path (a leaf, e.g. "ps") is a
    terminal `spec(positional="any")` - every family-wide admitted flag
    (global_flags/value_flags AND FAMILY_EXTRAS) stays admitted throughout
    via `inherit=True`. A node that is only a PREFIX of some longer path
    (e.g. "compose", or bq's "query") is intermediate: it admits no bare
    match and no stray positional of its own - it must hand off to one of
    its declared children, or the level fails (this is what keeps `bq
    query` bare, `docker system prune`, `flyctl apps destroy x`, `helm get
    values x`, `gh pr merge` etc. from slipping through as an unrelated
    "positional" at the intermediate level). An intermediate node's OWN
    grammar is limited to `family_bool`/`family_value` - the TRUE, old,
    dated `cli_families.FAMILIES` global_flags/value_flags, which old's
    flat `effective_verbs()` scan always treated as skippable at ANY
    position (`gh issue --repo o/r list` interposes `--repo` between the
    two verb tokens, and old admitted it - value_flags are deliberately
    position-transparent by original design). FAMILY_EXTRAS flags are
    NOT given to intermediate nodes: those are new admissions this task
    adds, so a multi-token verb path must still match with NO extra flag
    interposed between its own tokens (old never declared them at all, so
    `docker stats -a --no-stream` - "-a" is a FAMILY_EXTRAS addition, not
    an old value_flag - stays rejected, matching old exactly)."""
    terminal_paths = set(ro_verbs)
    intermediate_own = spec(bool=family_bool, value=family_value or {})
    root = {}
    for path in ro_verbs:
        level = root
        for i in range(len(path)):
            tok = path[i]
            level.setdefault(tok, {})
            level = level[tok]
    def _freeze(level_dict, path_prefix):
        out = {}
        for tok, children in level_dict.items():
            path = path_prefix + (tok,)
            frozen_children = _freeze(children, path)
            if frozen_children:
                # inherit=False here on purpose: a MULTI-token verb path
                # must match with NO family_extras flag interposed between
                # its own tokens - see docstring above.
                node = dict(intermediate_own)
                node["verbs"] = frozen_children
                node["require_verb"] = path not in terminal_paths
                node["inherit"] = False
                if path in terminal_paths:
                    # both a complete path AND a prefix of a longer one
                    # (not present in current data, handled for safety):
                    # bare match is fine here, deeper paths stay reachable.
                    node = dict(node)
                    node["require_verb"] = False
                    node["positional"] = "any"
                    node["inherit"] = True
            else:
                node = spec(positional="any", inherit=True)
            out[tok] = node
        return out
    return _freeze(root, ())


def _family_spec(head):
    fam = cli_families.FAMILIES[head]
    extra = FAMILY_EXTRAS.get(head, {"bool": (), "value": {}})
    family_bool = tuple(fam["global_flags"])
    family_value = {f: "any" for f in fam.get("value_flags", ())}
    bool_flags = family_bool + tuple(extra["bool"])
    value_flags = dict(family_value)
    value_flags.update(extra["value"])
    return spec(
        bool=bool_flags,
        value=value_flags,
        verbs=_verb_tree(fam["ro_verbs"], family_bool, family_value),
        require_verb=True,
    )


for _head in cli_families.FAMILIES:
    if _head not in HEAD_SPECS:
        HEAD_SPECS[_head] = _family_spec(_head)
