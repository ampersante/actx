"""Compact-flag conventions for the heads of waves 0-2 (TK-45, wave-3 plan).

Pure data + two pure functions, single import: shlex (inside hint_for
only). One source for all three consumers (INV-01): the Tier-2 instruction
table (installer.INSTRUCTION_SECTION via render_tier2), Tier-1 hook hints
(hook.py via hint_for, allow+rewrite verdicts only) and insights
suggestions (TK-46). Data edits here, not new predicates.

Entry schema (per head, ordered - first match wins):
  verb_prefix   -- token tuple the tokens AFTER the head must start with
                   (exact equality on every element; empty () always
                   matches, so it must sit LAST among a head's entries).
                   NOT a substring match: `git login` never matches
                   `git log` (A1, tested).
  missing_flags -- compact-output flag tokens; the advice fires only when
                   NONE of them is present in the tokens. Two-token forms
                   are deliberately not used: exact-token equality on a
                   list of single tokens keeps matching dumb and safe.
                   An =-form twin (`--max-count=50`) of a flag means the
                   flag is already present - it is listed as its own token.
  advice        -- one line, starts with the concrete compact form.
  tier2         -- True when the entry may appear in render_tier2(); the
                   Tier-2 table is a curated subset (frequency priority:
                   git / kubectl / docker / pytest / cloud / SQL), not
                   every CONVENTIONS record - the block stays <=30
                   content lines (stop-trigger 4).

Hint eligibility is a separate axis from tier2: records whose compact form
is safe for EVERY invocation (git log -n, pytest, kubectl get -o json)
serve as hook hints; records that would change semantics of a specific
usage (`git status --porcelain` alters the output FORMAT, not its volume)
stay Tier-2-only advice - so bare `git status` keeps its hook contract
byte-identical (test_hook.py:107).

Flags verified against the official CLI docs on 2026-09-05 (precedent:
cli_families doc line). Additions stay conservative - when in doubt,
leave the entry out (wave-2 canon).
"""

CONVENTIONS = {
    # git: -n/--max-count bound history volume; --stat/--porcelain are
    # format changes, not volume reducers -> Tier-2 table only.
    "git": (
        (
            ("log",),
            ("-n", "--max-count", "--oneline"),
            "add -n N (e.g. git log -n 50 --oneline)",
            True,
        ),
    ),
    # find: unbounded whole-tree walks; -maxdepth bounds them.
    "find": (
        (
            (),
            ("-maxdepth",),
            "add -maxdepth N to bound the tree walk",
            False,
        ),
    ),
    # test runners: -q/--quiet trims the per-test output.
    "pytest": (
        (
            (),
            ("-q", "--quiet", "--no-header"),
            "add -q (quiet dots) to trim the report",
            True,
        ),
    ),
    "jest": (
        (
            (),
            ("--silent",),
            "add --silent to trim the report",
            False,
        ),
    ),
    "vitest": (
        (
            (),
            ("--silent", "--reporter=dot", "--reporter=basic"),
            "add --silent or --reporter=dot to trim the report",
            False,
        ),
    ),
    "golangci-lint": (
        (
            (),
            ("--quiet",),
            "add --quiet (issues-only report)",
            False,
        ),
    ),
    # tsc: --pretty off removes the styled error formatting.
    "tsc": (
        (
            (),
            ("--pretty", "--noEmit"),
            "add --pretty false --noEmit for a terse check",
            False,
        ),
    ),
    # docker: --format trims ps to needed columns; inspect is already JSON
    # (no record - advice would be noise).
    "docker": (
        (
            ("ps",),
            ("--format",),
            "add --format '{{.Names}}\\t{{.Status}}' to keep two columns",
            True,
        ),
    ),
    # kubectl: scripting prefers structured output over wide tables.
    "kubectl": (
        (
            ("get",),
            ("-o", "--output"),
            "add -o json (or -o wide) for scripting-friendly output",
            True,
        ),
        (
            ("describe",),
            ("-o", "--output"),
            "not every describe output compresses - prefer kubectl get -o json when scripting",
            False,
        ),
    ),
    # mobile stack.
    "flutter": (
        (
            ("test",),
            ("--reporter",),
            "add --reporter compact to trim the run report",
            True,
        ),
    ),
    "xcodebuild": (
        (
            (),
            ("-quiet",),
            "add -quiet to print warnings/errors only",
            True,
        ),
    ),
    # data heads: LIMIT the payload; the =-forms of -c/--command keep the
    # SQL inside one token, so the missing_flags check never misreads it.
    "psql": (
        (
            (),
            ("LIMIT",),
            "add LIMIT n to bound row output",
            True,
        ),
    ),
    "sqlite3": (
        (
            (),
            ("LIMIT",),
            "add LIMIT n to bound row output",
            False,
        ),
    ),
    "duckdb": (
        (
            (),
            ("LIMIT",),
            "add LIMIT n to bound row output",
            False,
        ),
    ),
    # bq: JSON output auto-detects on runner.run; --format=json is the
    # compact form of the single-token =-family (cli_families precedent).
    "bq": (
        (
            (),
            ("--format=json",),
            "add --format=json for machine-readable output",
            False,
        ),
    ),
    # terraform: -no-color drops the ANSI escape flood of plan/apply logs.
    "terraform": (
        (
            ("plan",),
            ("-no-color",),
            "add -no-color to drop ANSI escapes",
            True,
        ),
    ),
    # dbt: --select scopes a run to specific models.
    "dbt": (
        (
            (),
            ("--select", "-s"),
            "add --select <model> to scope the run",
            True,
        ),
    ),
}

# Curated wave 1-2 head set (TK-46 adoption report; 26 heads per its DoD).
# Deliberately a literal list, NOT an intersection with FAMILIES:
# REGISTRY has 56 heads and FAMILIES only 13, so a formula silently
# drops the mobile and SQL heads (E-025/N-F1) - coverage would be a lie.
WAVE_HEADS = frozenset({
    # 7 cloud
    "vercel", "netlify", "railway", "wrangler", "supabase", "flyctl",
    "gcloud",
    # 3 infra
    "docker", "kubectl", "helm",
    # 9 mobile
    "flutter", "dart", "swift", "swiftlint", "swiftformat", "xcodebuild",
    "xcrun", "pod", "./gradlew",
    # 7 data
    "psql", "sqlite3", "duckdb", "bq", "terraform", "redis-cli", "dbt",
})


def _flag_present(tokens, flag):
    """True when a flag token is already present. Exact token equality,
    or the single-token ``flag=value`` =-form (the value never leaves the
    token, rewriter precedent). SQL LIMIT additionally matches as a word
    inside a compound payload token - `-c "SELECT ... LIMIT 10"` keeps the
    whole statement in one token after shlex.split."""
    for tok in tokens:
        if tok == flag:
            return True
        if flag.startswith("-") and tok.startswith(flag + "="):
            return True
        if flag == "LIMIT" and flag in tok.split():
            return True
    return False


def hint_for(command):
    """Advice line for a verbose-form command, or None.

    Pure: shlex.split (unclosed quote -> ValueError -> None), then token
    matching per the CONVENTIONS doc line. Never raises, never parses
    semantics - a 2 ms hook budget helper, not a shell language engine.
    """
    import shlex

    try:
        tokens = shlex.split(command)
    except ValueError:
        return None
    if not tokens:
        return None
    head = tokens[0]
    entries = CONVENTIONS.get(head)
    if not entries:
        return None
    rest = tokens[1:]
    for verb_prefix, missing_flags, advice, _tier2 in entries:
        if tuple(rest[: len(verb_prefix)]) == verb_prefix:
            if not any(_flag_present(tokens, flag) for flag in missing_flags):
                return advice
            return None  # flag already present - nothing to advise
    return None


def render_tier2():
    """Markdown block (without the trailing newline) listing the curated
    compact-flag conventions. Total by construction: pure data in,
    deterministic string out - the installer compares the body for
    replace-in-place, so two calls must be byte-identical (tested)."""
    lines = [
        "Prefer compact flags (less output to read before any filter):",
        "- `git log -n 50 --oneline` instead of a bare `git log`",
        "- `git status --porcelain` / `git diff --stat` / `git show -s` — machine-readable, short forms",
        "- `find -maxdepth N` instead of whole-tree walks",
        "- `pytest -q` / `jest --silent` — quiet test reports",
        "- `docker ps --format '{{.Names}}\\t{{.Status}}'` instead of the wide table",
        "- `kubectl get -o json` (or `-o wide`) instead of the full table when scripting",
        "- `flutter test --reporter compact`",
        "- `xcodebuild -quiet` — warnings and errors only",
        "- `psql -c 'SELECT … LIMIT n'` — always LIMIT row output (same for sqlite3/duckdb)",
        "- `bq --format=json` — machine-readable output",
        "- `terraform plan -no-color`",
        "- `dbt run --select <model>` instead of whole-project runs",
    ]
    return "\n".join(lines)
