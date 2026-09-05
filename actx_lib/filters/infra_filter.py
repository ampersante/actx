import json

from actx_lib import cli_families, runner
from actx_lib.filters import json_compactor
from actx_lib.redaction import (
    _SECRET_PATTERNS,
    _drop_secret_json,
    _drop_secret_lines,
    _is_secret_key,
)

# Mask widened in actx_lib.redaction (api_key, apikey, private_key, ...);
# redacts more of aws/docker/kubectl/gh output — safe direction.


def _rle(text):
    lines = text.split("\n")
    out = []
    index = 0
    while index < len(lines):
        line = lines[index]
        end = index + 1
        while end < len(lines) and lines[end] == line:
            end += 1
        count = end - index
        if count == 1:
            out.append(line)
        else:
            out.append("%s (x%d)" % (line, count))
        index = end
    return "\n".join(out)


def _dedup_compact(text):
    return _rle(_drop_secret_lines(text))


def compact_aws(text):
    compacted = json_compactor.compact_json(
        text, indent=2, sort_keys=True, max_items=None
    )
    if compacted is not None:
        return compacted
    return _dedup_compact(text)


def _compact_json_output(text):
    """compact_aws pattern (TK-38/TK-40): valid JSON -> secret-masked
    compact dump; anything else -> the dedup path (fail-open)."""
    compacted = json_compactor.compact_json(
        text, indent=2, sort_keys=True, max_items=None
    )
    if compacted is not None:
        return compacted
    return _dedup_compact(text)


def _run_compact(args, config, parser):
    cmd = list(args)
    result = runner.execute(cmd)
    if result is None:
        return 1
    return runner.compacted_result(
        cmd, result, config, runner.stdout_compactor(parser), strategy="infra"
    )


# Local effective-verb skip (TK-41, H-F4): global docker flags before the
# verb are skipped; the value-taking globals --context/-H/--host consume
# their value (`=` forms are single tokens and skip as plain flags).
# cli_families.effective_verbs arrives with TK-40 and will replace this;
# deliberately minimal, do not widen.
_DOCKER_VALUE_FLAGS = ("--context", "-H", "--host")
# compose-level flags that sit between `compose` and its subcommand.
_COMPOSE_VALUE_FLAGS = (
    "-f", "--file", "-p", "--project-name", "--profile", "--env-file",
)


def _first_verb(args, value_flags):
    """Tokens from the first non-flag verb onward; None when flags only."""
    idx = 0
    n = len(args)
    while idx < n:
        tok = args[idx]
        if tok in value_flags:
            idx += 2
            continue
        if tok.startswith("-"):
            idx += 1
            continue
        return args[idx:]
    return None


def run_docker(args, config):
    if not args:
        return runner.run_passthrough(["docker"])
    # Dispatch on the EFFECTIVE verb, not args[0]: global flags and their
    # values may precede it (docker --context prod ps).
    verbs = _first_verb(args, _DOCKER_VALUE_FLAGS)
    if verbs is None:
        return runner.run_passthrough(["docker"] + args)
    sub = verbs[0]
    if sub == "inspect":
        # JSON array output: compact_aws pattern (json_compactor + text
        # fallback via _dedup_compact).
        return _run_compact(["docker"] + args, config, compact_aws)
    if sub in ("ps", "images", "logs"):
        return _run_compact(["docker"] + args, config, _dedup_compact)
    if sub == "stats" and "--no-stream" in verbs[1:]:
        # Bare `docker stats` streams: it never reaches the parser — the
        # passthrough below refuses it via hang_policy (exit 125).
        return _run_compact(["docker"] + args, config, _dedup_compact)
    if sub == "system" and verbs[1:2] == ["df"]:
        return _run_compact(["docker"] + args, config, _dedup_compact)
    if sub == "compose":
        tail = _first_verb(verbs[1:], _COMPOSE_VALUE_FLAGS)
        if tail is not None and tail[0] in ("ps", "logs"):
            return _run_compact(["docker"] + args, config, _dedup_compact)
    return runner.run_passthrough(["docker"] + args)


def _has_json_output_flag(args):
    """True when the argv asks kubectl for machine-readable JSON output
    (`-o json`, `-o jsonpath...`). The jsonpath form is usually not valid
    JSON - _compact_json_output then fails open to the dedup path."""
    for i, tok in enumerate(args):
        if tok == "-o" and i + 1 < len(args):
            nxt = args[i + 1]
            if nxt == "json" or nxt.startswith("jsonpath"):
                return True
    return False


# TK-40: dispatch by EFFECTIVE verbs (cli_families.effective_verbs), not by
# args[0] - `kubectl -n prod get pods` must compact, not passthrough (H-F4).
_KUBECTL_COMPACT_SUBS = frozenset(
    {"get", "describe", "top", "events", "logs"}
)


def run_kubectl(args, config):
    if not args:
        return runner.run_passthrough(["kubectl"])
    verbs = cli_families.effective_verbs(["kubectl"] + args)
    sub = verbs[0] if verbs else None
    if sub in _KUBECTL_COMPACT_SUBS:
        parser = _dedup_compact
        if _has_json_output_flag(args):
            parser = _compact_json_output
        return _run_compact(["kubectl"] + args, config, parser)
    return runner.run_passthrough(["kubectl"] + args)


# TK-40: helm compaction subset (plan §4 E2). String dedup only - helm
# template/values output is YAML and no parser is allowed here; `helm get
# values` never reaches this list (stream_specs -> never-wrap, exit 125)
# and `helm show values/chart` stay raw passthrough by spec.
_HELM_COMPACT_SUBS = (
    ("template",),
    ("get", "metadata"),
    ("list",),
    ("status",),
    ("history",),
)


def run_helm(args, config):
    if not args:
        return runner.run_passthrough(["helm"])
    verbs = cli_families.effective_verbs(["helm"] + args)
    for sub in _HELM_COMPACT_SUBS:
        if tuple(verbs[: len(sub)]) == sub:
            return _run_compact(["helm"] + args, config, _dedup_compact)
    return runner.run_passthrough(["helm"] + args)


def run_gh(args, config):
    if not args:
        return runner.run_passthrough(["gh"])
    sub = args[0]
    if sub in ("pr", "issue", "run"):
        return _run_compact(["gh"] + args, config, _dedup_compact)
    return runner.run_passthrough(["gh"] + args)


def run_aws(args, config):
    if not args:
        return runner.run_passthrough(["aws"])
    return _run_compact(["aws"] + args, config, compact_aws)
