import os
import sys

from actx_lib import runner

_GREP_PASSTHROUGH = {
    "-h", "-l", "-c", "-o", "-q", "--quiet", "--silent",
    "-s", "-Z", "--color", "--colour", "--null",
}

_GREP_PREFIXES = (
    "-A", "-B", "-C",
    "--after-context=", "--before-context=", "--context=",
    "--color=", "--colour=",
)

_FIND_PASSTHROUGH = {
    "-print0", "-printf", "-ls", "-delete", "-exec", "-execdir",
    "-ok", "-okdir", "-fprint", "-fprintf", "-fls",
}


def _clip(text, limit):
    if len(text) <= limit:
        return text
    return text[:limit]


def run_ls(args, config):
    if any(arg.startswith("-") for arg in args) or len(args) > 1:
        return runner.run_passthrough(["ls"] + args)
    cmd = ["ls", "-1"] + args
    result = runner.execute(cmd)
    if result is None:
        return 1
    if result.returncode != 0:
        return runner.run_passthrough(["ls"] + args)

    try:
        path = args[0] if args else "."
        if os.path.isfile(path) and not os.path.isdir(path):
            print(os.path.basename(path))
            return 0

        entries = [line for line in result.stdout.split("\n") if line]
        dirs = []
        files = []
        for entry in entries:
            if os.path.isdir(os.path.join(path, entry)):
                dirs.append(entry)
            else:
                files.append(entry)
        dirs.sort()
        files.sort()

        display = path.rstrip("/")
        out = ["%s/ (%d)" % (display, len(entries))]
        if len(entries) <= 30:
            out.extend("  " + entry for entry in dirs + files)
        else:
            shown_dirs = dirs[:10]
            shown_files = files[:10]
            out.extend("  " + entry for entry in shown_dirs + shown_files)
            remaining = len(entries) - len(shown_dirs) - len(shown_files)
            out.append("  ... (%d more)" % remaining)
        print("\n".join(out))
        return 0
    except Exception:
        return runner.raw_fallback(result)


def _grep_passthrough(args):
    for arg in args:
        if arg in _GREP_PASSTHROUGH or arg.startswith(_GREP_PREFIXES):
            return True
    return False


def run_grep(args, config):
    if _grep_passthrough(args):
        return runner.run_passthrough(["grep"] + args)
    cmd = ["grep"] + args
    result = runner.execute(cmd)
    if result is None:
        return 1
    if result.returncode == 1:
        print("no matches")
        return 1
    if result.returncode >= 2:
        runner.print_raw(result)
        if runner.tee_decision(config, "auto", result.returncode):
            runner.write_tee(cmd, result, config)
        return result.returncode
    if len(result.stdout) <= 1000:
        runner.print_raw(result)
        return result.returncode

    try:
        groups = {}
        binary = []
        for line in result.stdout.split("\n"):
            if not line:
                continue
            if line.startswith("Binary file "):
                binary.append(line)
            elif ":" in line:
                file, rest = line.split(":", 1)
                groups.setdefault(file, []).append(_clip(rest, 200))
            else:
                groups.setdefault("(no path)", []).append(_clip(line, 200))

        out = list(binary)
        for file, matches in groups.items():
            out.append("%s: %d matches" % (file, len(matches)))
            out.extend("  " + match for match in matches[:5])
            if len(matches) > 5:
                out.append("  ...")
        if out:
            print("\n".join(out))
        return 0
    except Exception:
        return runner.raw_fallback(result)


def run_find(args, config):
    if any(arg in _FIND_PASSTHROUGH for arg in args):
        return runner.run_passthrough(["find"] + args)
    cmd = ["find"] + args
    result = runner.execute(cmd)
    if result is None:
        return 1
    if result.returncode != 0:
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)
        if runner.tee_decision(config, "auto", result.returncode):
            runner.write_tee(cmd, result, config)
        return result.returncode
    if len(result.stdout) <= 200:
        runner.print_raw(result)
        return result.returncode

    try:
        dirs = {}
        for line in result.stdout.split("\n"):
            if not line:
                continue
            dirname, basename = os.path.split(line)
            dirs.setdefault(dirname, []).append(basename)

        total_dirs = len(dirs)
        out = []
        for dirname, names in list(dirs.items())[:200]:
            names = sorted(set(names))
            out.append("%s (%d):" % (dirname, len(names)))
            out.extend("  " + name for name in names[:10])
            if len(names) > 10:
                out.append("  ... (%d more)" % (len(names) - 10))
        if total_dirs > 200:
            out.append("... (%d more dirs)" % (total_dirs - 200))
        if out:
            print("\n".join(out))
        return 0
    except Exception:
        return runner.raw_fallback(result)
