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

Source per head, in order of preference: (1) exact rewrite corpus token
usage (`tests/fixtures/rewrite_corpus.json` - every admitted spelling below
that is not independently footnoted is drawn from a POSITIVE corpus
example); (2) tables already vetted with a dated citation elsewhere in this
codebase (`cli_families.FAMILIES`, `cli_families.GRADLE_*`, the pflag_short
bool/value character sets and `_CARGO_*` tables that used to live in
`rewriter.py` before this module existed) - reused verbatim, never
re-derived; (3) a small number of live `--help`/`man` pulls done for this
task (git, grep, docker, kubectl - noted inline) where the head is
security-relevant and heavily used. A head absent from HEAD_SPECS has NO
confirmed source and does not rewrite at all (TK-60 stop rule) - see the
stream report's loss list for the reasoning per head.
"""

from actx_lib import cli_families

# Owned here (single source); rewriter.py re-exports it under the same name
# so `filters/git_filter.py`'s existing `from actx_lib.rewriter import
# BRANCH_READ_ONLY` keeps working unchanged.
BRANCH_READ_ONLY = frozenset({
    "-a", "-r", "-l", "--list", "--show-current",
    "-v", "--verbose", "-vv", "--no-color",
})


def spec(verbs=None, bool=(), value=None, optional=None, numeric=False,
         cluster=False, positional="none", after_dashdash="forbid",
         hook=None, inherit=False, require_verb=False,
         dashdash_literals=("--",), require_any_of=()):
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
        # at least one of these literal tokens must appear somewhere in
        # the tail for this level to match (cargo fmt/metadata/package
        # each require exactly one specific flag; swiftformat/xcodebuild
        # require one of several) - empty tuple means no such constraint.
        "require_any_of": frozenset(require_any_of),
    }


# ---------------------------------------------------------------------
# Independent grammars matched after a `--`/boundary hand-off
# (cargo's forwarded libtest/rustfmt args, go test's forwarded test-binary
# args - REQ-07/after_dashdash "forward"). Each is itself a full `spec()`,
# matched against the tokens that follow the boundary exactly like a head
# grammar would be.
# ---------------------------------------------------------------------
FORWARD_SPECS = {
    # `cargo test -- <libtest args>` / `cargo clippy -- <rustc args>` never
    # rewrite today for ANY forwarded content (the old dispatch only saw
    # `cargo` without a forward path at all - _cargo_ok inspects cargo_args
    # only, forwarded_args are ignored, i.e. never validated, so nothing
    # was ever admitted through `--` for these subcommands). "forbid" here
    # is behavior-preserving: `cargo clippy -- -D warnings` (POS example)
    # in fact means `--` never reached the OLD predicate as `cargo_args`,
    # it went to forwarded_args - re-checked against the exact corpus in
    # W4; see the stream report for the resolution actually shipped.
    "cargo_fmt_forward": spec(
        bool=("--check",),
        value={"--emit": frozenset({"files", "file"})},
        positional="none",
    ),
    # `cargo clippy -- <rustc lint flags>` (corpus positive: `cargo clippy
    # -- -D warnings`) - rustc's lint-level flags only; anything else
    # after `--` for clippy is a new, deliberate tightening vs. the old
    # fully-unchecked forwarded_args (loss-list candidate, not a
    # regression since old never validated these either way - RO-safe
    # direction).
    "cargo_clippy_forward": spec(
        value={"-D": "any", "-W": "any", "-A": "any",
               "--deny": "any", "--warn": "any", "--allow": "any"},
        positional="none",
    ),
}


# ---------------------------------------------------------------------
# git (installed locally; `git log/diff/show/status -h`, `git push/pull/
# fetch -h` re-checked 2026-09-27). No global flags admitted before the
# subcommand (today's dispatch requires tokens[1] to literally be the verb -
# `git -C x status` is not in the exact corpus and was never admitted).
# ---------------------------------------------------------------------
_GIT_LOG_DIFF_SHOW_BOOL = (
    "--oneline", "--graph", "--all", "--decorate", "--no-decorate",
    "--stat", "--name-only", "--name-status", "-p", "--patch",
    "--no-merges", "--merges", "--first-parent", "--cached", "--staged",
    "--color", "--no-color",
)
_GIT_LOG_DIFF_SHOW_VALUE = {
    "--author": "any", "--since": "any", "--until": "any",
    "--grep": "any", "--format": "any", "--pretty": "any",
    "--max-count": "int", "-n": "int",
}

HEAD_SPECS = {
    "git": spec(verbs={
        "status": spec(bool=("-s", "--short", "-b", "--branch"),
                        positional="any"),
        "log": spec(bool=_GIT_LOG_DIFF_SHOW_BOOL, value=_GIT_LOG_DIFF_SHOW_VALUE,
                    numeric=True, positional="any"),
        "diff": spec(bool=_GIT_LOG_DIFF_SHOW_BOOL, value=_GIT_LOG_DIFF_SHOW_VALUE,
                     positional="any"),
        "show": spec(bool=_GIT_LOG_DIFF_SHOW_BOOL, value=_GIT_LOG_DIFF_SHOW_VALUE,
                     positional="any"),
        "blame": spec(positional="any"),
        "rev-parse": spec(bool=("--short", "--verify", "--is-inside-work-tree"),
                           positional="any"),
        "add": spec(bool=("-A", "--all", "-p", "--patch", "-u", "--update",
                          "-n", "--dry-run", "-v", "--verbose"),
                    positional="any"),
        "commit": spec(value={"-m": "any", "--message": "any"}, positional="any"),
        "push": spec(bool=("-f", "--force", "--force-with-lease", "--tags",
                           "--dry-run", "-v", "--verbose", "-u", "--set-upstream"),
                     value={"--recurse-submodules": frozenset({"check", "on-demand", "no", "yes"})},
                     positional="any"),
        "pull": spec(bool=("--rebase", "--ff-only", "--no-rebase", "-v", "--verbose"),
                     positional="any"),
        "fetch": spec(bool=("--all", "--tags", "--prune", "--dry-run",
                            "-v", "--verbose"),
                      positional="any"),
        "branch": spec(bool=BRANCH_READ_ONLY, positional="none"),
        "stash": spec(require_verb=True, verbs={
            "list": spec(positional="none"),
        }),
    }, require_verb=True),
}


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
# ls (the old `_LS_FLAGS`/`_ls_ok` cluster set reused verbatim: exact
# listed combinations only, at most one path, and the path must be
# non-empty - `ls ""` must not rewrite, closed via the `nonempty_positional`
# hook since the generic positional slot has no built-in emptiness check).
HEAD_SPECS["ls"] = spec(
    bool=("-l", "-a", "-la", "-al", "-lh", "-lah", "-ahl", "-hal", "-hla",
          "-alh", "-1", "-F"),
    positional=("max", 1),
    hook="nonempty_positional",
)


HEAD_SPECS["grep"] = spec(
    bool=tuple(f"-{c}" for c in "abcdDEFGHhIiJLlMmnOopqRSsUVvwXxZz") + (
        "--line-buffered", "--null", "-r", "-R", "--recursive", "--color",
    ),
    value={
        "-A": "int", "-B": "int", "-e": "any", "-f": "any",
        "--binary-files": "any", "--directories": "any", "--label": "any",
        "--include": "any", "--exclude": "any", "--exclude-dir": "any",
    },
    optional={"-C": "int", "--context": "int", "--color": "any"},
    cluster=True,
    positional="any",
)


# ---------------------------------------------------------------------
# rg (ripgrep; installed - `rg --help` semantics well known: `--pre`/
# `--pre-glob`/`--hostname-bin` exec an arbitrary preprocessor per file,
# already excluded here by simply never listing them, closing the prior
# open-grammar hole for every OTHER rg flag in the same step).
# ---------------------------------------------------------------------
HEAD_SPECS["rg"] = spec(
    bool=("-i", "--ignore-case", "-v", "--invert-match", "-n", "--line-number",
          "-c", "--count", "-l", "--files-with-matches", "-L",
          "--files-without-match", "-w", "--word-regexp", "-x", "--line-regexp",
          "-o", "--only-matching", "-s", "--case-sensitive", "-U", "--multiline",
          "-a", "--text", "-F", "--fixed-strings", "-P", "--pcre2",
          "--hidden", "--no-ignore", "--color"),
    value={"-e": "any", "-g": "any", "--glob": "any", "-t": "any",
           "--type": "any", "-m": "int", "--max-count": "int",
           "-A": "int", "-B": "int", "-C": "int"},
    cluster=True,
    positional="any",
)


# ---------------------------------------------------------------------
# cat / tree / wc / head / tail / sort / uniq - the classic RO toolbox.
# Denied write-path flags (sort -o/--output/--compress-program, tree
# -o/--output) are closed simply by never listing them.
# ---------------------------------------------------------------------
HEAD_SPECS["cat"] = spec(bool=("-n", "--number", "-b", "--number-nonblank",
                               "-s", "--squeeze-blank", "-A", "-e", "-t", "-v"),
                          positional="any")
HEAD_SPECS["tree"] = spec(bool=("-a", "-d", "-f", "-i", "-L", "-C", "-h",
                                "--du", "-s", "-p", "-u", "-g", "-D", "-F",
                                "-Q", "-N"),
                           value={"-I": "any", "-P": "any"},
                           positional="any")
HEAD_SPECS["wc"] = spec(bool=("-l", "-c", "-m", "-w", "-L"), positional="any")
HEAD_SPECS["head"] = spec(bool=("-c", "-n", "-q", "-v"), numeric=True,
                           value={"-n": "int", "-c": "int"}, positional="any")
HEAD_SPECS["tail"] = spec(numeric=True, value={"-n": "int", "-c": "int"},
                           positional="any")  # -f/--follow: never listed (stream/hang, TK-55)
HEAD_SPECS["sort"] = spec(bool=("-u", "-r", "-n", "-f", "-b", "-c", "-k",
                                "-t", "-M", "-h", "-R"),
                           value={"-k": "any", "-t": "any"}, positional="any")
HEAD_SPECS["uniq"] = spec(bool=("-c", "-d", "-u", "-i"),
                           value={"-f": "int", "-s": "int", "-w": "int",
                                  "--skip-fields": "int", "--skip-chars": "int",
                                  "--check-chars": "int"},
                           positional=("max", 1))


# ---------------------------------------------------------------------
# find (BSD find; `man find` re-checked 2026-09-27). Every write/exec
# primary (-delete/-exec/-execdir/-ok/-okdir/-fprint/-fprint0/-fprintf/
# -fls) is closed by simply never declaring it - no forbidden-set/hook
# needed any more (TK-57 STEP-04b's -fprint0 sibling gap cannot recur:
# unknown primaries fail closed by construction).
# ---------------------------------------------------------------------
HEAD_SPECS["find"] = spec(
    bool=("-d", "-s", "-x", "-H", "-L", "-P", "-X", "-depth", "-empty",
          "-print", "-print0", "!", "-not", "-a", "-and", "-o", "-or"),
    value={"-name": "any", "-iname": "any", "-path": "any", "-ipath": "any",
           "-regex": "any", "-iregex": "any", "-type": "any",
           "-maxdepth": "int", "-mindepth": "int", "-size": "any",
           "-mtime": "any", "-atime": "any", "-ctime": "any",
           "-mmin": "any", "-amin": "any", "-cmin": "any",
           "-newer": "any", "-perm": "any", "-user": "any", "-group": "any"},
    positional="any",
)


# ---------------------------------------------------------------------
# Test runners / linters already effectively-open (no verb, whole
# invocation is a flag bag). Closed to the flags the exact corpus and the
# existing per-head denylist comments (siblings already enumerated when
# TK-55/57 added the deny entries) jointly establish are legitimate.
# ---------------------------------------------------------------------
HEAD_SPECS["pytest"] = spec(
    bool=("-q", "--quiet", "-v", "--verbose", "-x", "--exitfirst", "-s",
          "--capture=no", "--tb=short", "--tb=long", "--tb=line",
          "--tb=native", "--collect-only", "--co", "-ra", "-rf", "-rs"),
    value={"-k": "any", "-m": "any", "--junit-prefix": "any",
           "--maxfail": "int"},
    positional="any",
)
HEAD_SPECS["jest"] = spec(
    bool=("-o", "--onlyChanged", "--ci", "--silent", "--verbose",
          "--runInBand", "--detectOpenHandles", "--passWithNoTests"),
    value={"-t": "any", "--testNamePattern": "any", "--testPathPattern": "any",
           "--maxWorkers": "any"},
    positional="any",
)
HEAD_SPECS["vitest"] = spec(
    bool=("--ci", "--silent", "--passWithNoTests"),
    value={"-t": "any", "--testNamePattern": "any", "--reporter": "any"},
    positional="any",
)
HEAD_SPECS["tsc"] = spec(
    bool=("--noEmit", "--strict", "--pretty", "--listFiles", "--listEmittedFiles"),
    value={"--project": "any"},
    positional="any",
)
HEAD_SPECS["ruff"] = spec(verbs={
    "check": spec(positional="any"),
}, require_verb=True)
HEAD_SPECS["eslint"] = spec(bool=(), positional="any")
_NEXT_VERB_LEVEL = spec(positional="any")
HEAD_SPECS["next"] = spec(verbs={
    "lint": _NEXT_VERB_LEVEL, "build": _NEXT_VERB_LEVEL, "info": _NEXT_VERB_LEVEL,
}, require_verb=True)


# ---------------------------------------------------------------------
# cargo (`_CARGO_1ARG_FLAGS`/`_CARGO_2ARG_FLAGS` reused verbatim - these
# were already an exhaustive, dated flag table, not re-derived).
# ---------------------------------------------------------------------
_CARGO_ROOT_BOOL = ("-q", "--quiet", "-v", "-vv", "--verbose",
                    "--offline", "--locked", "--frozen")
_CARGO_ROOT_VALUE = {"--color": frozenset({"auto", "always", "never"}),
                     "--config": "any", "-C": "any", "-Z": "any",
                     "--manifest-path": "any", "--target-dir": "any"}
HEAD_SPECS["cargo"] = spec(
    bool=_CARGO_ROOT_BOOL,
    value=_CARGO_ROOT_VALUE,
    positional=("max", 1),
    hook="cargo_toolchain",  # a bare leading "+<toolchain>" token, if any
    verbs={
        "check": spec(inherit=True, positional="any"),
        "test": spec(inherit=True, positional="any", after_dashdash="forbid"),
        "build": spec(inherit=True, positional="any"),
        "tree": spec(inherit=True, positional="any"),
        "clippy": spec(inherit=True, bool=("--all-targets", "--all"),
                        after_dashdash=("forward", "cargo_clippy_forward"),
                        positional="any"),
        "fmt": spec(inherit=True, bool=("--all", "--check"),
                    after_dashdash=("forward", "cargo_fmt_forward"),
                    require_any_of=("--check",),
                    positional="none"),
        "metadata": spec(inherit=True, bool=("--no-deps",), positional="none",
                          require_any_of=("--no-deps",)),
        "package": spec(inherit=True, bool=("--list",), positional="none",
                         require_any_of=("--list",)),
    },
    require_verb=True,
)


# ---------------------------------------------------------------------
# go test (corpus + existing `_DENIED_WRITE_FLAGS["go"]` name-set: the
# write/profile flags o/c/coverprofile/cpuprofile/memprofile/blockprofile/
# mutexprofile/trace/outputdir are closed simply by never declaring them;
# `-args` ends the go flag space exactly like `--` elsewhere.
# ---------------------------------------------------------------------
HEAD_SPECS["go"] = spec(verbs={
    "test": spec(
        # go's flag package treats "-x" and "--x" identically (dash-count
        # equivalence, AGENTS.md security-surface note) - both spellings
        # declared explicitly (no abbreviation logic in the engine).
        bool=("-v", "--v", "-short", "--short", "-race", "--race",
              "-cover", "--cover"),
        value={"-run": "any", "--run": "any", "-count": "int", "--count": "int"},
        positional="any",
        # `-args`/`--args` ends go's own flag space; the old dispatch
        # simply stopped scanning at this point (unrestricted beyond it -
        # the compiled test binary's own flag namespace), so "positional"
        # (accept anything) here is behavior-preserving, not a new hole:
        # go's own write/profile flags (-o/-c/-coverprofile/...) are
        # already closed above by never being declared.
        after_dashdash="positional",
        dashdash_literals=("-args", "--args"),
    ),
}, require_verb=True)


# ---------------------------------------------------------------------
# pip / uv / npm / pnpm (existing RO verb-name tables reused verbatim).
# ---------------------------------------------------------------------
HEAD_SPECS["pip"] = spec(verbs={v: spec(positional="any")
                                for v in ("list", "show", "freeze", "outdated")},
                          require_verb=True)
HEAD_SPECS["npm"] = spec(verbs={"list": spec(positional="any")}, require_verb=True)
HEAD_SPECS["pnpm"] = spec(verbs={"list": spec(positional="any")}, require_verb=True)
# `uv` itself is NOT a HEAD_SPECS entry: `uv run <inner>` is a run-prefix
# (REQ-07) - the engine unwraps it via cli_families.run_prefix_split
# (which independently validates uv's own `run` flags) and then matches
# the INNER command against ITS OWN entry here; a `uv` entry would be
# unreachable dead data (the engine never dispatches "uv" itself).


# ---------------------------------------------------------------------
# Mobile toolchains (TK-42) - existing RO verb sets reused verbatim.
# ---------------------------------------------------------------------
HEAD_SPECS["flutter"] = spec(verbs={
    "doctor": spec(positional="none"),
    "analyze": spec(positional="any"),
    "test": spec(value={"--plain-name": "any"}, positional="any"),
    "pub": spec(verbs={
        "outdated": spec(positional="any"),
        "deps": spec(bool=("--style=compact",), positional="any"),
    }, require_verb=True),
}, require_verb=True)
HEAD_SPECS["dart"] = spec(verbs={
    "analyze": spec(positional="any"),
    "test": spec(value={"--name": "any"}, positional="any"),
}, require_verb=True)
HEAD_SPECS["swift"] = spec(verbs={
    "build": spec(value={"--product": "any"}, positional="any"),
    "test": spec(value={"--filter": "any"}, positional="any"),
}, require_verb=True)
HEAD_SPECS["swiftlint"] = spec(verbs={
    "lint": spec(bool=("--strict",), positional="any"),
}, require_verb=True)
HEAD_SPECS["swiftformat"] = spec(
    bool=("--lint", "--dryrun", "--dry-run"), positional="any",
    require_any_of=("--lint", "--dryrun", "--dry-run"),
)
HEAD_SPECS["xcodebuild"] = spec(
    bool=("-list", "-showsdks", "-showBuildSettings"),
    value={"-project": "any", "-scheme": "any", "-destination": "any"},
    positional="any",
    require_any_of=("-list", "-showsdks", "-showBuildSettings",
                     "-scheme", "-destination"),
)
# `xcrun` itself is not an entry (same run-prefix reasoning as `uv`
# above): `xcrun simctl <verb>` unwraps to the inner head "simctl", which
# IS the entry actually matched.
HEAD_SPECS["simctl"] = spec(verbs={"list": spec(positional="any")},
                             require_verb=True)
HEAD_SPECS["pod"] = spec(verbs={v: spec(positional="any")
                                for v in ("outdated", "list")}, require_verb=True)


# ---------------------------------------------------------------------
# ./gradlew - flags come straight from cli_families.GRADLE_* (already an
# exhaustive dated table); only the per-positional TASK classification
# needs a hook (REQ-06: cli_families.gradle_task_class, reused verbatim).
# ---------------------------------------------------------------------
HEAD_SPECS["./gradlew"] = spec(
    bool=cli_families.GRADLE_BOOL_FLAGS,
    value={f: "any" for f in cli_families.GRADLE_VALUE_FLAGS},
    positional="any",
    hook="gradle_task",
)


# ---------------------------------------------------------------------
# SQL CLIs (psql/sqlite3/duckdb) - flag grammar closed from the exact
# corpus' positive spellings; `sql_payload` hook (REQ-06) reuses
# `sql_verbs.sql_payloads`/`classify_payload` verbatim for the actual RO/
# dangerous classification of the SQL text itself (never duplicated).
# File-based SQL (`-f`/`--file`/`-init`) and admin flags (`-cmd`, `-A`/
# `--A`, `-append`, `-unsafe-testing`, `-zip`) are closed simply by never
# declaring them - this also supersedes the old explicit SQL_FILE_FLAGS
# reject (same effect, one mechanism).
# ---------------------------------------------------------------------
HEAD_SPECS["psql"] = spec(
    bool=("-t", "--tuples-only", "-A", "--no-align", "-q", "--quiet",
          "-X", "--no-psqlrc"),
    value={"-c": "any", "--command": "any", "-d": "any", "--dbname": "any",
           "-h": "any", "--host": "any", "-p": "any", "--port": "any",
           "-U": "any", "--username": "any"},
    positional="any",
    hook="sql_payload",
)
HEAD_SPECS["sqlite3"] = spec(
    bool=("-json", "-readonly", "-list", "-csv", "-line", "-header",
          "-noheader", "-batch", "-bail"),
    value={"-separator": "any", "-cmd": "any", "--cmd": "any"},
    positional=("max", 2),
    hook="sql_payload",
)
HEAD_SPECS["duckdb"] = spec(
    bool=("-json", "-readonly", "-list", "-csv", "-line", "-header",
          "-noheader"),
    value={"-c": "any", "-s": "any", "-cmd": "any", "--cmd": "any"},
    positional=("max", 2),
    hook="sql_payload",
)


HEAD_SPECS["dbt"] = spec(verbs={v: spec(value={"--select": "any"}, positional="any")
                                for v in ("run", "test", "build")}, require_verb=True)


# ---------------------------------------------------------------------
# terraform (family ro_verbs reused; the flag-sensitive `plan -out` form
# stays excluded by simply never declaring `-out`/`-out=`).
# ---------------------------------------------------------------------
HEAD_SPECS["terraform"] = spec(verbs={
    "plan": spec(bool=("-input=false",), positional="any"),
    "validate": spec(positional="any"),
    "show": spec(positional="any"),
    "version": spec(positional="none"),
    "graph": spec(positional="any"),
}, require_verb=True)


# =======================================================================
# Cloud/pflag families (docker TK-41, kubectl/helm TK-40, bq/terraform/
# redis-cli TK-43, gh TK-55, vercel/netlify/railway/wrangler/supabase/
# flyctl/gcloud wave-1): derived from `cli_families.FAMILIES` (already a
# dated, docs-cited table) plus FAMILY_EXTRAS - additional bool/value
# flags confirmed either by a live `--help` pull this task (docker,
# kubectl - both re-checked 2026-09-27) or already present with a dated
# citation in the OLD `rewriter._DENIED_WRITE_FLAGS[...]["pflag_short"]`
# tables (kubectl/docker bool/value short-char sets, verified against
# `kubectl get/describe/top/events/logs --help` + `kubectl options`,
# 2026-09-26) - never re-derived, only translated into named flags.
# A family's ro_verbs sequences are reused as this head's verb paths.
# =======================================================================
FAMILY_EXTRAS = {
    "docker": {
        # -f/--follow (docker logs/compose logs; corpus: `docker compose
        # logs -f`) is boolean, NOT the `docker ps -f`/`--filter` value
        # flag - keeping it boolean-only avoids accidentally admitting
        # `docker compose -f <file> ps` (a value--flag pair there would
        # let a bogus alternate compose file slip through the ro_verbs
        # prefix match; `-f`/`--filter` (query filter) is deliberately
        # NOT added - not in the exact corpus, loss-list candidate).
        "bool": ("-a", "--all", "-q", "--quiet", "-l", "--latest", "-s",
                 "--size", "--no-trunc", "--digests", "--details",
                 "-t", "--timestamps", "--tree", "-f", "--follow",
                 "-v", "--verbose"),
        "value": {"-n": "any", "--last": "any", "--tail": "any",
                  "--since": "any", "--until": "any"},
    },
    "kubectl": {
        # short chars A/w/R/p already boolean via pflag_short (2026-09-26);
        # o/n/l/f/k/L/c/v value - long spellings added where confirmed by
        # `kubectl get --help` (2026-09-27): -o/--output, -l/--selector,
        # -f/--filename, -k/--kustomize, -L/--label-columns, -w/--watch,
        # -R/--recursive. -c/-v long forms not independently confirmed
        # this session - short forms only (fail-closed direction).
        "bool": ("-w", "--watch", "-R", "--recursive", "-p", "--previous"),
        "value": {"-o": "any", "--output": "any", "-l": "any",
                  "--selector": "any", "-f": "any", "--filename": "any",
                  "-k": "any", "--kustomize": "any",
                  "-L": "any", "--label-columns": "any",
                  "-c": "any", "-v": "any"},
    },
    "helm": {
        # --output json (corpus positive; distinct from the denied
        # --output-dir which is never listed here).
        "bool": (),
        "value": {"--output": "any"},
    },
    "gcloud": {"bool": (), "value": {}},
    "bq": {"bool": (), "value": {}},
    "vercel": {"bool": (), "value": {}},
    "netlify": {"bool": (), "value": {}},
    "railway": {"bool": (), "value": {}},
    "wrangler": {"bool": (), "value": {}},
    "supabase": {"bool": (), "value": {}},
    "flyctl": {"bool": (), "value": {}},
    "gh": {"bool": (), "value": {}},
    "terraform": {"bool": (), "value": {}},
    "redis-cli": {"bool": (), "value": {}},
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
