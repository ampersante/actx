import os
import sys

from actx_lib import runner

_C_COMMENT_EXTS = {".js", ".ts", ".c", ".h", ".cpp", ".java", ".rs", ".go"}


def _is_py_comment(index, line):
    stripped = line.lstrip()
    if index == 0:
        return stripped.startswith("#") and not stripped.startswith("#!")
    return stripped.startswith("#")


def run(args, config):
    if not args:
        print("error: read requires a file", file=sys.stderr)
        return 1
    file = args[0]
    level = "none"
    if len(args) >= 2:
        if args[1] != "--level" or len(args) < 3:
            print("error: read expects --level <level>", file=sys.stderr)
            return 1
        level = args[2]
    if level == "aggressive":
        print("error: --level aggressive is not supported", file=sys.stderr)
        return 1
    if level not in ("none", "minimal"):
        print("error: unknown level: %s" % level, file=sys.stderr)
        return 1

    if level == "none":
        return runner.run_passthrough(["cat", file])

    ext = os.path.splitext(file)[1].lower()
    if ext != ".py" and ext not in _C_COMMENT_EXTS:
        return runner.run_passthrough(["cat", file])

    cmd = ["cat", file]
    result = runner.execute(cmd)
    if result is None:
        return 1
    if result.returncode != 0:
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)
        if runner.tee_decision(config, "auto", result.returncode):
            runner.write_tee(cmd, result, config)
        return result.returncode

    try:
        lines = result.stdout.split("\n")
        if ext == ".py":
            kept = [
                line for i, line in enumerate(lines)
                if not _is_py_comment(i, line)
            ]
        else:
            kept = [
                line for line in lines
                if not line.lstrip().startswith("//")
            ]
        out = "\n".join(kept)
        if out:
            print(out, end="")
        return 0
    except Exception:
        return runner.raw_fallback(result)
