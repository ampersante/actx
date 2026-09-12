import os
import shlex

from actx_lib import cli_families, sql_verbs

_FORBIDDEN = set("\n\r\t\0;&&|<>$`(){}#")

# Owned here so rewriter never imports filters (hook/rewrite perf boundary).
BRANCH_READ_ONLY = frozenset({
    "-a", "-r", "-l", "--list", "--show-current",
    "-v", "--verbose", "-vv", "--no-color",
})

_LS_FLAGS = frozenset({
    "-l", "-a", "-la", "-al", "-lh", "-lah", "-ahl", "-hal", "-hla", "-alh",
    "-1", "-F",
})

_GIT_RO = frozenset({"status", "diff", "log", "show", "blame", "rev-parse"})
_GIT_MUTATE = frozenset({"add", "commit", "push", "pull", "fetch"})

_PIP_RO = frozenset({"list", "show", "freeze", "outdated"})
# TK-51 (user policy 2026-09-05): install-class verbs left the mutator
# allow-list (roll-back of v2.3.0) — package installs are never rewritten;
# the T5 security gate escalates them to "ask" on the hook path instead.
_NPM_RO = frozenset({"list"})
_CARGO_PURE_RO = frozenset({"check", "test", "build", "tree"})
_CARGO_1ARG_FLAGS = frozenset({
    "-q", "--quiet", "-v", "-vv", "-vvv", "--verbose",
    "--offline", "--locked", "--frozen",
})
_CARGO_2ARG_FLAGS = frozenset({
    "--color", "--config", "-C", "-Z", "--manifest-path", "--target-dir",
})

_WRITE_TOKENS = frozenset({"--fix", "fix", "format"})

# TK-55 F3: flags whose value is a write path / output redirect on
# otherwise-RO heads (rule: "the flag's value is a file the command
# writes"). Per-head match kinds:
#   eq      -- `tok == flag` or the `flag=value` single-token form
#   attach  -- one-letter short flag, bare or with a glued value
#              (`-o out`, `-oout`); only for non-"--" tokens
#   prefix  -- plain startswith (`git --out*` catches --output too)
#   name    -- dash-insensitive name match: go's flag package accepts
#              `--flag` == `-flag` verbatim, so the stored name (no dashes)
#              is compared to `tok.lstrip("-").split("=",1)[0]`
#   nameci  -- same as `name` but case-insensitive (tsc strips 1-2 leading
#              dashes and matches option names case-insensitively)
# The scan runs on the EFFECTIVE head: inside `uv run <argv>` /
# `xcrun simctl <argv>` the inner head is matched (cli_families
# run_prefix_split, shared with the security gate). This table folds in
# the former per-predicate `sort -o`/`--output` and `git --out*` rejects.
_DENIED_WRITE_FLAGS = {
    "git": {"prefix": ("--out",)},
    # getopt_long resolves unambiguous abbreviations (verified on Apple
    # sort: `sort --o file` writes); --output is the only --o* long option.
    # --compress-program=<prog> execs the program on temp-file spills
    # (GNU; accepted-but-inert on BSD sort).
    "sort": {"eq": ("--compress-program",), "prefix": ("--o",),
             "attach": ("-o",)},
    # GNU tree resolves long-option abbreviations (`--out` -> --output);
    # on BSD tree long options don't exist and the flag simply errors.
    "tree": {"prefix": ("--o",), "attach": ("-o",)},
    # jest uses yargs: dashed spellings map onto the camelCase options.
    # -u/--updateSnapshot rewrites inline snapshots in source files —
    # the --fix sibling (source-mutation flag).
    "jest": {"eq": ("--outputFile", "--output-file",
                    "--coverageDirectory", "--coverage-directory",
                    "--updateSnapshot", "--update-snapshot", "--update"),
             "attach": ("-u",)},
    "vitest": {"eq": ("--outputFile", "--output-file", "--update"),
               "attach": ("-u",),
               "prefix": ("--outputFile.", "--output-file.")},
    # optionator accepts unambiguous long-option abbreviations (any
    # non-empty prefix of --output-file: --o, --ou, --out, ...); it is the
    # only --o* long option in eslint's space.
    "eslint": {"eq": ("--output-file",), "attach": ("-o",),
               "prefix": ("--o",)},
    # --add-noqa rewrites source files in place (sibling of --fix).
    "ruff": {"eq": ("--output-file", "--cache-dir", "--add-noqa"),
             "attach": ("-o",)},
    "go": {"name": ("o", "c", "coverprofile", "cpuprofile", "memprofile",
                    "blockprofile", "mutexprofile", "trace", "outputdir")},
    # --init writes tsconfig.json (file-creation flag).
    "tsc": {"nameci": ("out", "outfile", "outdir", "declarationdir",
                       "tsbuildinfofile", "generatetrace", "init")},
    # pytest's parser allows unambiguous abbreviations; "--junitx"/
    # "--junit-x" cover every prefix of both --junitxml and --junit-xml
    # without catching the RO --junit-prefix flag.
    "pytest": {"eq": ("--basetemp", "--junitxml", "--junit-xml"),
               "prefix": ("--junitx", "--junit-x", "--baset")},
    # Acceptance residuals (pre-existing holes, same defer outcome):
    # rg --pre/--pre-glob execute an arbitrary command per file —
    # exec-capable, not a write flag, but refused here by the same
    # mechanism ("--pretty" pins the eq form: a "--pre" prefix would FP).
    "rg": {"eq": ("--pre", "--pre-glob", "--hostname-bin")},
    # psql -o/--output and -L/--log-file write query output to files; psql
    # uses getopt_long, so abbreviations resolve too (--o and --lo are
    # unique; --l would collide with --list).
    "psql": {"prefix": ("--o", "--lo"), "attach": ("-o", "-L")},
    # getopt_long abbreviations of --follow (--f/--fo/...) defeat the
    # never-wrap check and would hang the wrapper — defer instead.
    "tail": {"prefix": ("--f",), "attach": ("-f", "-F")},
    # `helm template --output-dir <dir>` writes every rendered manifest;
    # helm (pflag) has no abbreviations. Eq only: `helm list --output`
    # is a legit RO format flag. --post-renderer execs the named program;
    # the prefix also covers --post-renderer-args.
    "helm": {"eq": ("--output-dir",), "prefix": ("--post-renderer",)},
    # `terraform plan -out[=]<file>` writes a plan file (canonical
    # single-dash form of the documented =-form gap).
    "terraform": {"eq": ("-out",)},
}


def _has_denied_write_flag(head, argv):
    """True when a token of argv (the tokens after the effective head)
    carries a denied write-path flag of `head` (TK-55 F3). For `go` the
    scan stops at `-args`: flags behind it belong to the test binary, not
    to the go tool."""
    spec = _DENIED_WRITE_FLAGS.get(head)
    if spec is None:
        return False
    for tok in argv:
        # go: `-args`/`--args` ends the go flag space; what follows belongs
        # to the test binary, not to the go tool.
        if head == "go" and tok.lstrip("-") == "args":
            break
        for flag in spec.get("eq", ()):
            if tok == flag or tok.startswith(flag + "="):
                return True
        if not tok.startswith("--"):
            for flag in spec.get("attach", ()):
                if tok.startswith(flag):
                    return True
        for flag in spec.get("prefix", ()):
            if tok.startswith(flag):
                return True
        if tok.startswith("-"):
            name = tok.lstrip("-").split("=", 1)[0]
            # go test accepts test-binary flags under the `-test.` prefix
            # verbatim (`go test -test.coverprofile=x` writes the file).
            if head == "go" and name.startswith("test."):
                name = name[5:]
            for flag in spec.get("name", ()):
                if name == flag:
                    return True
            lname = name.lower()
            for flag in spec.get("nameci", ()):
                if lname == flag:
                    return True
    return False


def _parse_cargo(tokens):
    """Extracts (subcmd, cargo_args, forwarded_args) from cargo tokens."""
    idx = 1
    n = len(tokens)
    while idx < n:
        tok = tokens[idx]
        if tok == "--":
            return None, [], []
        if tok.startswith("+"):
            idx += 1
            continue
        if tok in _CARGO_1ARG_FLAGS:
            idx += 1
            continue
        if tok in _CARGO_2ARG_FLAGS:
            idx += 2
            continue
        if tok.startswith("--color=") or tok.startswith("--config=") or tok.startswith("-C=") or tok.startswith("-Z="):
            idx += 1
            continue
        if tok.startswith("-"):
            idx += 1
            continue
        subcmd = tok
        rest = tokens[idx + 1 :]
        if "--" in rest:
            dash_idx = rest.index("--")
            cargo_args = rest[:dash_idx]
            forwarded_args = rest[dash_idx + 1 :]
        else:
            cargo_args = rest
            forwarded_args = []
        return subcmd, cargo_args, forwarded_args
    return None, [], []


def _cargo_ok(tokens):
    if len(tokens) < 2:
        return False
    subcmd, cargo_args, forwarded_args = _parse_cargo(tokens)
    if subcmd is None:
        return False

    if subcmd in _CARGO_PURE_RO:
        return True

    if subcmd == "clippy":
        return not any(tok == "--fix" or tok.startswith("--fix=") for tok in cargo_args)

    if subcmd == "fmt":
        all_args = cargo_args + forwarded_args
        has_check = "--check" in all_args
        has_emit_files = False
        for i, tok in enumerate(all_args):
            if tok in ("--emit=files", "--emit=file"):
                has_emit_files = True
                break
            if tok == "--emit" and i + 1 < len(all_args) and all_args[i + 1] in ("files", "file"):
                has_emit_files = True
                break
        return has_check and not has_emit_files

    if subcmd == "metadata":
        return "--no-deps" in cargo_args

    if subcmd == "package":
        return "--list" in cargo_args

    return False



def _has_write_token(tokens):
    return any(tok in _WRITE_TOKENS or tok.startswith("--fix") for tok in tokens[1:])


def _git_ok(tokens):
    if len(tokens) < 2:
        return False
    sub = tokens[1]
    if sub in _GIT_RO:
        return True
    if sub in _GIT_MUTATE:
        return True
    if sub == "branch":
        rest = tokens[2:]
        return (not rest) or all(arg in BRANCH_READ_ONLY for arg in rest)
    if sub == "stash" and len(tokens) >= 3 and tokens[2] == "list":
        return True
    return False


def _ls_ok(tokens):
    rest = tokens[1:]
    if not rest:
        return True
    flags = []
    paths = []
    for tok in rest:
        if tok.startswith("-"):
            flags.append(tok)
        else:
            paths.append(tok)
    if len(paths) > 1:
        return False
    if any(not p for p in paths):
        return False
    if flags and any(f not in _LS_FLAGS for f in flags):
        return False
    return True


def _find_ok(tokens):
    forbidden = {
        "-delete", "-exec", "-execdir", "-ok", "-okdir",
        "-fprint", "-fprintf", "-fls",
    }
    return forbidden.isdisjoint(tokens)


def _wc_family_ok(tokens):
    head = tokens[0]
    if head == "tail" and any(
        tok == "-f" or tok == "--follow" or tok.startswith("--follow=")
        for tok in tokens
    ):
        return False
    if head == "uniq":
        # POSIX `uniq [input [output]]`: a second positional is a write
        # path — skip uniq's value-flags (-f/-s/-w and long forms) first.
        positionals = 0
        idx = 1
        while idx < len(tokens):
            tok = tokens[idx]
            if tok in ("-f", "-s", "-w", "--skip-fields",
                       "--skip-chars", "--check-chars"):
                idx += 2
                continue
            if tok.startswith("-"):
                idx += 1
                continue
            positionals += 1
            idx += 1
        if positionals >= 2:
            return False
    return True


def _pip_ok(tokens):
    if len(tokens) < 2:
        return False
    return tokens[1] in _PIP_RO


def _uv_ok(tokens):
    # TK-51: `uv pip install` left the allow-list; `uv run` stays (primary
    # semantics: run — the install matrix lives in the T5 gate).
    # TK-55: the inner head must be locatable — an unparseable `uv run`
    # (unknown flag, bare `run`) defers instead of being auto-approved.
    if len(tokens) < 2 or tokens[1] != "run":
        return False
    return cli_families.run_prefix_split(tokens) is not None


def _npm_ok(tokens):
    if len(tokens) < 2:
        return False
    return tokens[1] in _NPM_RO


def _ruff_ok(tokens):
    return not _has_write_token(tokens)


def _eslint_ok(tokens):
    return not _has_write_token(tokens)


def _next_ok(tokens):
    return not any(tok == "--fix" or tok.startswith("--fix") for tok in tokens[1:])


# --- mobile toolchains (TK-42) ---
_FLUTTER_RO = frozenset({"doctor", "analyze", "test"})
_DART_RO = frozenset({"analyze", "test"})
_SWIFT_RO = frozenset({"build", "test"})
_XCODEBUILD_INFO_FLAGS = frozenset({"-list", "-showsdks", "-showBuildSettings"})
_SWIFTFORMAT_READONLY = frozenset({"--lint", "--dryrun", "--dry-run"})

# --- SQL CLIs (TK-43, REQ-06): the ONLY heads with the quote-aware guard ---
_SQL_HEADS = frozenset({"psql", "sqlite3", "duckdb"})


def _flutter_ok(tokens):
    if len(tokens) < 2:
        return False
    if tokens[1] == "doctor":
        # License acceptance is an interactive prompt (never-wrap upstream).
        return "--android-licenses" not in tokens[2:]
    if tokens[1] in _FLUTTER_RO:
        return True
    return (
        tokens[1] == "pub"
        and len(tokens) >= 3
        and tokens[2] in ("outdated", "deps")
    )


def _swiftformat_ok(tokens):
    # Mutating mode (bare, paths, fix/format) never matches: the read-only
    # lint/dry flags are required verbatim and write tokens reject outright.
    if _has_write_token(tokens):
        return False
    return any(tok in _SWIFTFORMAT_READONLY for tok in tokens[1:])


def _xcodebuild_ok(tokens):
    rest = tokens[1:]
    # Interactive signing update prompts (never-wrap upstream).
    if "-allowProvisioningUpdates" in rest:
        return False
    if any(tok in _XCODEBUILD_INFO_FLAGS for tok in rest):
        return True
    # A build pinned to a scheme/destination compacts to diagnostics only;
    # the bare invocation stays unwrapped (interactive signing prompts).
    return "-scheme" in rest or "-destination" in rest


def _gradlew_ok(tokens):
    """./gradlew dispatch (TK-55 F5): every positional token is a gradle
    task and must classify "ro" via cli_families.gradle_task_class —
    multi-task invocations rewrite only when ALL tasks are RO
    (`publish`/`clean`-class and unknown verbs defer). Declared gradle
    value flags are skipped with their value (separate or `=`-form),
    `-P...`/`-D...` glued properties and declared boolean flags are
    skipped whole; an undeclared `-`-token fails closed. Bare `./gradlew`
    keeps rewriting (parity with the former always-true predicate —
    default tasks)."""
    args = tokens[1:]
    i = 0
    n = len(args)
    while i < n:
        tok = args[i]
        if tok in cli_families.GRADLE_VALUE_FLAGS:
            i += 2  # flag + separate value token
            continue
        if any(
            tok.startswith(vf + "=")
            for vf in cli_families.GRADLE_VALUE_FLAGS
        ):
            i += 1  # --flag=value: value stays inside the token
            continue
        if tok.startswith(cli_families.GRADLE_ATTACHED_VALUE_PREFIXES):
            i += 1  # glued -Pprop=v / -Dprop=v
            continue
        if tok in cli_families.GRADLE_BOOL_FLAGS:
            i += 1
            continue
        if tok.startswith("-"):
            return False  # undeclared flag: fail closed
        if cli_families.gradle_task_class(tok) != "ro":
            return False
        i += 1
    return True


def _quoted_token(tok):
    """True when the token starts AND ends with a quote char (shlex
    posix=False keeps the quotes inside the token)."""
    return len(tok) >= 2 and tok[0] in "'\"" and tok[-1] in "'\""


def _c_payload_tokens(rest):
    """(index, token) of every -c/--command payload token; a missing value
    yields (index, None)."""
    out = []
    i = 0
    n = len(rest)
    while i < n:
        if rest[i] in ("-c", "--command"):
            out.append((i + 1, rest[i + 1] if i + 1 < n else None))
            i += 2
            continue
        i += 1
    return out


def _sql_guard_ok(command):
    """Quote-aware guard for SQL heads (TK-43, wave-2 plan section 3 /
    H-F1/N-F8). Replaces the raw metachar reject for `_SQL_HEADS` ONLY:

    - `shlex.split(command, posix=False)` keeps the quotes in the tokens;
      an unclosed quote raises ValueError -> reject.
    - Every `_FORBIDDEN` metacharacter of the command must sit inside a
      token that starts AND ends with a quote (shell-injected unquoted
      metachars like `psql -c SELECT 1; rm -rf /` reject).
    - The payload must be a SINGLE quoted token after `-c` (psql/duckdb,
      every occurrence) or the last positional at >=2 positionals
      (sqlite3) - else reject.

    Structural only; the SQL class (RO vs dangerous) is decided by the
    dispatch predicate below, so guard and predicate both must pass."""
    try:
        toks = shlex.split(command, posix=False)
    except ValueError:
        return False  # unclosed quote
    if not toks or toks[0] not in _SQL_HEADS:
        return False
    for tok in toks:
        if any(ch in _FORBIDDEN for ch in tok) and not _quoted_token(tok):
            return False
    rest = toks[1:]
    payloads = _c_payload_tokens(rest)
    if payloads:
        return all(tok is not None and _quoted_token(tok) for _, tok in payloads)
    if toks[0] == "sqlite3":
        positionals = [tok for tok in rest if not tok.startswith("-")]
        return len(positionals) >= 2 and _quoted_token(positionals[-1])
    return False


def _sql_cli_ok(tokens):
    """psql/sqlite3/duckdb dispatch predicate (TK-43): every SQL payload
    (sql_verbs.sql_payloads - one shared extraction with the security
    gate) must classify RO; file-based SQL (`-f`/`--file`/`-init`) never
    rewrites; no payload (bare REPL) never rewrites (hang policy owns it,
    exit 125)."""
    rest = tokens[1:]
    if any(
        tok in sql_verbs.SQL_FILE_FLAGS or tok.startswith("--file=")
        for tok in rest
    ):
        return False
    payloads = sql_verbs.sql_payloads(tokens[0], rest)
    if not payloads:
        return False
    return all(sql_verbs.classify_payload(p) == "ro" for p in payloads)


_DBT_RO = frozenset({"run", "test", "build"})


def _terraform_ok(tokens):
    """terraform dispatch (TK-43): the family ro_verbs generation EXCEPT the
    flag-sensitive `plan -out <file>` form - a persisted plan is what a
    later `terraform apply` executes without re-reading the diff. A plain
    prefix table cannot express the exclusion, so terraform keeps a manual
    predicate here (rewriter-side twin of the hang-policy dedicated
    predicates; the T6 ask spec itself lives in FAMILIES). Limitation
    (documented): the `-out=file` =-form is a single token and slips this
    token check, same as the T6 matcher."""
    if "-out" in tokens[1:]:
        return False
    return _cloud_family_ok(
        tokens, cli_families.FAMILIES["terraform"]["ro_verbs"]
    )


# head -> predicate(tokens) ; None predicate means always rewrite when head matches
_DISPATCH = {
    "git": _git_ok,
    "ls": _ls_ok,
    "grep": lambda _t: True,
    "find": _find_ok,
    "wc": _wc_family_ok,
    "head": _wc_family_ok,
    "tail": _wc_family_ok,
    "sort": _wc_family_ok,
    "uniq": _wc_family_ok,
    "rg": lambda _t: True,
    "cat": lambda _t: True,
    "tree": lambda _t: True,
    "pytest": lambda _t: True,
    "jest": lambda _t: True,
    "vitest": lambda _t: True,
    "ruff": _ruff_ok,
    "eslint": _eslint_ok,
    "golangci-lint": lambda t: not _has_write_token(t),
    "tsc": lambda _t: True,
    "next": _next_ok,
    "cargo": _cargo_ok,
    "go": lambda t: len(t) >= 2 and t[1] == "test",
    "pip": _pip_ok,
    "uv": _uv_ok,
    "npm": _npm_ok,
    "pnpm": _npm_ok,
    # --- mobile toolchains (TK-42); "./gradlew" matches the argv token ---
    "flutter": _flutter_ok,
    "dart": lambda t: len(t) >= 2 and t[1] in _DART_RO,
    "swift": lambda t: len(t) >= 2 and t[1] in _SWIFT_RO,
    "swiftlint": lambda t: len(t) >= 2 and t[1] == "lint" and not _has_write_token(t),
    "swiftformat": _swiftformat_ok,
    "xcodebuild": _xcodebuild_ok,
    "xcrun": lambda t: len(t) >= 3 and t[1] == "simctl" and t[2] == "list",
    "pod": lambda t: len(t) >= 2 and t[1] in ("outdated", "list"),
    "./gradlew": _gradlew_ok,
    # --- data stack (TK-43); bq/redis-cli join via FAMILIES generation ---
    "psql": _sql_cli_ok,
    "sqlite3": _sql_cli_ok,
    "duckdb": _sql_cli_ok,
    "dbt": lambda t: len(t) >= 2 and t[1] in _DBT_RO,
    # terraform: family ro_verbs minus the `plan -out` form (manual entry -
    # the FAMILIES loop never overwrites manual predicates)
    "terraform": _terraform_ok,
}


def _cloud_family_ok(tokens, ro_verbs):
    """Family predicate: the effective verb tokens (head dropped; boolean
    global flags and value-flags-with-their-value skipped by
    cli_families.effective_verbs - the single skip-logic source) must start
    with one of the ro_verbs sequences (exact token equality on every
    element). Stream/secret verbs are simply absent from ro_verbs, so they
    never match here."""
    verbs = cli_families.effective_verbs(tokens)
    if verbs is None:
        return False
    for verb in ro_verbs:
        if tuple(verbs[: len(verb)]) == verb:
            return True
    return False


# CLI families join the dispatch from the declarative table (TK-39; docker
# in TK-41 and kubectl/helm in TK-40 — their manual predicates removed: no
# manual predicate may shadow a family head, or the generated predicate
# would silently never run); manual predicates above
# are never overwritten.
for _head, _spec in cli_families.FAMILIES.items():
    if _head not in _DISPATCH:
        _DISPATCH[_head] = (
            lambda t, _ro=_spec["ro_verbs"]: _cloud_family_ok(t, _ro)
        )


def rewrite(command):
    if not command:
        return None
    if command.startswith("actx "):
        return None
    if len(command) > 4096:
        return None
    if any(ch in _FORBIDDEN for ch in command):
        # TK-43 (wave-2 plan section 3, REQ-06): SQL heads swap the raw
        # metachar reject for the quote-aware guard (real SQL almost always
        # carries `;`/`()`); every other head keeps the strict byte-identical
        # guard - `git commit -m "fix; drop"` still rejects (red-gate 13).
        parts = command.split()
        head = parts[0] if parts else ""
        if head not in _SQL_HEADS:
            return None
        if not _sql_guard_ok(command):
            return None
    try:
        tokens = shlex.split(command)
    except ValueError:
        return None
    if not tokens:
        return None

    # TK-55 F3: denied write-path flags are checked on the EFFECTIVE
    # head — inside a run-prefix (`uv run <argv>`, `xcrun simctl <argv>`)
    # the inner argv is scanned, otherwise the command's own tail.
    inner = cli_families.run_prefix_split(tokens)
    if inner is not None:
        inner_argv, _consumed = inner
        w_head = os.path.basename(inner_argv[0])
        w_argv = inner_argv[1:]
    else:
        w_head = os.path.basename(tokens[0])
        w_argv = tokens[1:]
    if _has_denied_write_flag(w_head, w_argv):
        return None

    pred = _DISPATCH.get(tokens[0])
    if pred is None:
        return None
    if not pred(tokens):
        return None
    return "actx " + command
