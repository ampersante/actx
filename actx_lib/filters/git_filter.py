"""git summary verbs. diff/show/blame/stash list are the content class
(TK-61): cli.main runs them through runner.run_content and they never
reach this module."""

from actx_lib import runner
from actx_lib.rewriter import BRANCH_READ_ONLY

_LOG_PASSTHROUGH = {
    "-p", "--stat", "--graph", "--numstat", "--name-only",
    "--name-status", "--format", "--pretty",
}


def _failure(cmd, result, config):
    # stdout survives a failing exit (TK-61), then stderr.
    runner.print_lossless_stdout(cmd, result, config)
    return result.returncode


def _branch_name():
    result = runner.execute(["git", "symbolic-ref", "--short", "HEAD"])
    if result is None or result.returncode != 0:
        return None
    return result.stdout.strip()


def _group_status(porcelain):
    groups = []
    index = {}
    for line in porcelain.split("\n"):
        if not line:
            continue
        key = line[:2].strip()
        path = line[3:]
        if key not in index:
            index[key] = len(groups)
            groups.append((key, []))
        groups[index[key]][1].append(path)
    return groups


def _status(rest, config):
    if rest:
        return runner.run_passthrough(["git", "status"] + rest)
    cmd = ["git", "status", "--porcelain=v1"]
    result = runner.execute(cmd)
    if result is None:
        return 1
    if result.returncode != 0:
        return _failure(cmd, result, config)

    try:
        branch = _branch_name()
        groups = _group_status(result.stdout)
        out = []
        if config.get("ultra_compact"):
            if branch is not None:
                out.append("* " + branch)
            elif not groups:
                out.append("no commits yet")
            for key, paths in groups:
                shown = paths[:200]
                out.append("%s:%d %s" % (key, len(paths), " ".join(shown)))
                if len(paths) > 200:
                    out.append("  ... (%d more)" % (len(paths) - 200))
        else:
            if branch is not None:
                out.append("* " + branch)
            elif not groups:
                out.append("no commits yet")
            for key, paths in groups:
                out.append("%s (%d):" % (key, len(paths)))
                out.extend("  " + path for path in paths[:200])
                if len(paths) > 200:
                    out.append("  ... (%d more)" % (len(paths) - 200))
        text = "\n".join(out)
        extra = 0
        if any(len(paths) > 200 for _, paths in groups):
            # Paths omitted: the full porcelain stays recoverable (TK-61).
            tee_path = runner.tee_listing(cmd, result, text, config)
            extra = len("[full output: %s]\n" % tee_path) if tee_path else 0
        elif out:
            print(text)
        runner.record_compacted(cmd, result, text, "git.status", extra_bytes=extra)
        return 0
    except Exception:
        return runner.raw_fallback(result)


def _log(rest, config):
    if any(arg in _LOG_PASSTHROUGH for arg in rest):
        return runner.run_passthrough(["git", "log"] + rest)
    rest = [arg for arg in rest if arg != "--oneline"]
    cmd = ["git", "log", "--oneline"] + rest
    result = runner.execute(cmd)
    if result is None:
        return 1
    if result.returncode != 0:
        return _failure(cmd, result, config)
    try:
        if result.stdout:
            print(result.stdout, end="")
            if not result.stdout.endswith("\n"):
                print()
        runner.record_raw(cmd, result, "git.log")
        return 0
    except Exception:
        return runner.raw_fallback(result)


def _branch(rest, config):
    if not rest or all(arg in BRANCH_READ_ONLY for arg in rest):
        return runner.run_passthrough(["git", "branch"] + rest)
    cmd = ["git", "branch"] + rest
    result = runner.execute(cmd)
    if result is None:
        return 1
    if result.returncode != 0:
        return _failure(cmd, result, config)
    try:
        print("ok")
        runner.record_compacted(cmd, result, "ok", "git.branch")
        return 0
    except Exception:
        return runner.raw_fallback(result)


def _mutating(sub, rest, config):
    cmd = ["git", sub] + rest
    result = runner.execute(cmd)
    if result is None:
        return 1
    if result.returncode != 0:
        return _failure(cmd, result, config)
    try:
        if sub == "commit":
            rev = runner.execute(["git", "rev-parse", "--short", "HEAD"])
            if rev is not None and rev.returncode == 0:
                text = "ok %s" % rev.stdout.strip()
                print(text)
                runner.record_compacted(cmd, result, text, "git.mutating")
                return 0
        print("ok")
        runner.record_compacted(cmd, result, "ok", "git.mutating")
        return 0
    except Exception:
        return runner.raw_fallback(result)


def _rev_parse(rest, config):
    return runner.run_passthrough(["git", "rev-parse"] + rest)


def run(args, config):
    if not args:
        return runner.run_passthrough(["git"])
    sub = args[0]
    rest = args[1:]
    if sub == "status":
        return _status(rest, config)
    if sub == "log":
        return _log(rest, config)
    if sub == "branch":
        return _branch(rest, config)
    if sub == "rev-parse":
        return _rev_parse(rest, config)
    if sub in {"add", "commit", "push", "pull", "fetch"}:
        return _mutating(sub, rest, config)
    return runner.run_passthrough(["git"] + args)
