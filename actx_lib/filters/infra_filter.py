import json

from actx_lib import runner
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


def run_kubectl(args, config):
    if not args:
        return runner.run_passthrough(["kubectl"])
    sub = args[0]
    if sub == "logs":
        return _run_compact(["kubectl"] + args, config, _dedup_compact)
    if sub == "get":
        return _run_compact(["kubectl"] + args, config, _dedup_compact)
    return runner.run_passthrough(["kubectl"] + args)


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
