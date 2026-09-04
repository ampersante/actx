import json

from actx_lib import runner
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
    stripped = text.strip()
    try:
        obj = json.loads(stripped)
    except ValueError:
        return _dedup_compact(text)
    return json.dumps(_drop_secret_json(obj), indent=2, sort_keys=True)


def _run_compact(args, config, parser):
    cmd = list(args)
    result = runner.execute(cmd)
    if result is None:
        return 1
    return runner.compacted_result(
        cmd, result, config, runner.stdout_compactor(parser), strategy="infra"
    )


def run_docker(args, config):
    if not args:
        return runner.run_passthrough(["docker"])
    sub = args[0]
    if sub in ("ps", "images", "logs"):
        return _run_compact(["docker"] + args, config, _dedup_compact)
    if sub == "compose" and len(args) >= 2 and args[1] == "ps":
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
