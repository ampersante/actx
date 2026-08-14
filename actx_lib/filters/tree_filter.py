import fnmatch
import os
import sys

_MAX_ENTRIES = 200
_ENTRY_LIMIT = _MAX_ENTRIES - 1  # reserve one output line for the truncation marker


def _ignored_file(name, patterns):
    return any(fnmatch.fnmatch(name, pattern) for pattern in patterns)


def _render(path, ignore_dirs, ignore_files):
    lines = []
    shown = 0
    total = 0
    if path == "/":
        root_label = "/"
    else:
        root_label = path.rstrip("/") or "."

    for root, dirs, files in os.walk(path, topdown=True):
        dirs[:] = sorted(d for d in dirs if d not in ignore_dirs)
        files = sorted(
            f for f in files if not _ignored_file(f, ignore_files)
        )
        rel = os.path.relpath(root, path)
        if rel == ".":
            label = root_label
            depth = 0
        else:
            label = os.path.basename(root)
            depth = rel.count(os.sep) + 1

        total += 1
        if shown < _ENTRY_LIMIT:
            lines.append("%s%s (%d)" % ("  " * depth, label, len(files)))
            shown += 1
        for name in files:
            total += 1
            if shown < _ENTRY_LIMIT:
                lines.append("%s  %s" % ("  " * depth, name))
                shown += 1

    if total > shown:
        lines.append("... (%d more)" % (total - shown))
    return "\n".join(lines)


def run(args, config):
    if len(args) > 1:
        print("error: tree takes at most one path", file=sys.stderr)
        return 1
    path = args[0] if args else "."

    ignore_dirs = config.get("ignore_dirs", [])
    ignore_files = config.get("ignore_files", [])
    if not isinstance(ignore_dirs, list):
        ignore_dirs = []
    if not isinstance(ignore_files, list):
        ignore_files = []
    ignore_dirs = [item for item in ignore_dirs if isinstance(item, str)]
    ignore_files = [item for item in ignore_files if isinstance(item, str)]

    try:
        if not os.path.exists(path):
            print("tree: %s: No such file or directory" % path, file=sys.stderr)
            return 1
        print(_render(path, ignore_dirs, ignore_files))
        return 0
    except OSError as exc:
        print("tree: %s" % exc, file=sys.stderr)
        return 1
