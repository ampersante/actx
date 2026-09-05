"""Data-stack transport: SQL CLIs, terraform, redis-cli, dbt (TK-43).

Exec-array execution plus compaction (fail-open everywhere: any error
reaches raw stdout+stderr with the original exit code via the
runner.compacted_result / run_lossless contracts; PRD.md 8):

- psql / sqlite3 / duckdb -> column masking (headers matching the secret
  patterns) BEFORE ascii_table_filter.compact_table compaction - the
  redaction -> compression order of the TK-43 data-fidelity DoD; the mask
  keeps every cell width so pipe positions (the compaction contract) are
  untouched; output without a framed table falls back to secret-line
  redaction. Exit code preserved.
- terraform             -> plan/validate/show/version/graph dedup
                          compaction (infra_filter _run_compact pattern).
- redis-cli             -> RO verb subset through the lossless runner path
                          (collapse-dedup + explicit truncation markers,
                          raw fallback).
- dbt                   -> run/test/build failures-only via the declarative
                          dbt_run profile (test_runner_filter pattern).

Data fidelity notes (TK-43 DoD addition, documented at command level):
- Cell values are never re-typed: leading zeros (`007`), `+` prefixes and
  unicode survive verbatim (string ops only); padding whitespace around a
  value is stripped by the table compactor (documented approximation of
  the TK-44 contract); commas inside values make the output CSV-like, not
  strict CSV.
- Duplicate rows are NOT deduplicated on the SQL path (only consecutive
  identical lines collapse on the redis/generic lossless path, with an
  explicit [xN] marker).
"""

from actx_lib import cli_families, runner
from actx_lib.filters import ascii_table_filter, compact_profiles
from actx_lib.filters.infra_filter import _dedup_compact, _run_compact
from actx_lib.redaction import _SECRET_PATTERNS, redact_text

# _is_frame: the same frame detector the compactor uses, so masking and
# compaction can never disagree about what a table block is.
from actx_lib.filters.ascii_table_filter import _is_frame


# --- psql / sqlite3 / duckdb: masked table compaction ----------------------


def _mask_cell(cell):
    """`  s3cr3t  ` -> `  ***     `: masked, padded to the ORIGINAL cell
    width so the pipe positions of the framed row do not move (the
    compactor's interior-pipe alignment check stays satisfied)."""
    value = cell.strip()
    if not value:
        return cell
    width = len(value)
    masked = "*" * width if width < 3 else "***" + " " * (width - 3)
    lead = len(cell) - len(cell.lstrip(" "))
    trail = len(cell) - len(cell.rstrip(" "))
    return " " * lead + masked + " " * trail


def _secret_columns(header_cells):
    return {
        idx
        for idx, cell in enumerate(header_cells)
        if any(pattern in cell.lower() for pattern in _SECRET_PATTERNS)
    }


def _mask_block(block):
    """Mask data cells of one framed-table block; block unchanged when no
    header column matches a secret pattern or the rows are ragged (the
    compactor then falls back to raw, and _sql_compact adds line
    redaction)."""
    row_indexes = [k for k, line in enumerate(block) if line.startswith("|")]
    if len(row_indexes) < 2:
        return block
    header_cells = block[row_indexes[0]].split("|")
    secret = _secret_columns(header_cells)
    if not secret:
        return block
    out = list(block)
    for k in row_indexes[1:]:
        cells = block[k].split("|")
        if len(cells) != len(header_cells):
            continue  # ragged row: leave it to the compactor's raw fallback
        out[k] = "|".join(
            _mask_cell(cell) if idx in secret else cell
            for idx, cell in enumerate(cells)
        )
    return out


def _mask_secret_columns(text):
    """Column-mask every framed table of the text (fail-open: errors and
    table-less text return the input unchanged; when no column matches a
    secret pattern the ORIGINAL object is returned, so callers can detect
    "nothing was masked" with `is`)."""
    try:
        if not isinstance(text, str) or "|" not in text:
            return text
        lines = text.split("\n")
        out = []
        i = 0
        n = len(lines)
        while i < n:
            if not _is_frame(lines[i]):
                out.append(lines[i])
                i += 1
                continue
            j = i + 1
            while j < n and (_is_frame(lines[j]) or lines[j].startswith("|")):
                j += 1
            out.extend(_mask_block(lines[i:j]))
            i = j
        result = "\n".join(out)
        return text if result == text else result
    except Exception:
        return text


def _sql_compact(text):
    """SQL CLI output compaction: masking -> ascii_table compaction -> on
    any doubt (raw fallback) secret-line redaction only."""
    masked = _mask_secret_columns(text)
    compacted = ascii_table_filter.compact_table(masked)
    if compacted is not masked:
        return compacted
    return redact_text(masked)


def _sql_has_payload(cmd):
    rest = cmd[1:]
    if any(
        tok in ("-c", "--command") or tok.startswith("--command=")
        for tok in rest
    ):
        return True
    if cmd[0] == "sqlite3":
        return len([tok for tok in rest if not tok.startswith("-")]) >= 2
    return False


def _run_sql_cli(cmd, config):
    # Payload present -> masked table compaction; bare REPL / file SQL ->
    # passthrough (the hang policy refuses REPLs with exit 125 first).
    if _sql_has_payload(cmd):
        return _run_compact(cmd, config, _sql_compact)
    return runner.run_passthrough(cmd)


def run_psql(args, config):
    return _run_sql_cli(["psql"] + args, config)


def run_sqlite3(args, config):
    return _run_sql_cli(["sqlite3"] + args, config)


def run_duckdb(args, config):
    return _run_sql_cli(["duckdb"] + args, config)


# --- terraform: lossy-in-format, lossless-in-values dedup ------------------

_TERRAFORM_COMPACT_VERBS = (
    ("plan",), ("validate",), ("show",), ("version",), ("graph",),
)


def run_terraform(args, config):
    if not args:
        return runner.run_passthrough(["terraform"])
    verbs = cli_families.effective_verbs(["terraform"] + args)
    for verb in _TERRAFORM_COMPACT_VERBS:
        if tuple(verbs[: len(verb)]) == verb:
            return _run_compact(["terraform"] + args, config, _dedup_compact)
    return runner.run_passthrough(["terraform"] + args)


# --- redis-cli: factual small output on the lossless path ------------------

_REDIS_RO = frozenset(
    {"EXISTS", "TTL", "TYPE", "SCAN", "DBSIZE",
     "exists", "ttl", "type", "scan", "dbsize"}
)


def run_redis(args, config):
    """RO verb subset -> lossless runner path (ANSI strip + collapse-dedup
    with explicit markers + explicit truncation); anything else ->
    passthrough. GET/MONITOR never arrive wrapped (never-wrap, exit 125);
    destructive verbs ask on the hook path."""
    if not args:
        return runner.run_passthrough(["redis-cli"])
    verbs = cli_families.effective_verbs(["redis-cli"] + args)
    if verbs and verbs[0] in _REDIS_RO:
        return runner.run_lossless(
            ["redis-cli"] + args, config, strategy="data"
        )
    return runner.run_passthrough(["redis-cli"] + args)


# --- dbt: failures-only through the declarative profile --------------------

def _dbt_compact(text):
    data = compact_profiles.parse_test(text, compact_profiles.PROFILES["dbt_run"])
    parts = []
    if data["failures"].strip():
        parts.append(data["failures"])
    parts.append("%d failed, %d passed" % (data["failed"], data["passed"]))
    return "\n".join(parts)


def run_dbt(args, config):
    if not args:
        return runner.run_passthrough(["dbt"])
    if args[0] in ("run", "test", "build"):
        result = runner.execute(["dbt"] + args)
        if result is None:
            return 1
        return runner.compacted_result(
            ["dbt"] + args,
            result,
            config,
            runner.stdout_compactor(_dbt_compact),
            strategy="test",
        )
    return runner.run_passthrough(["dbt"] + args)
