import fnmatch
import os
import subprocess
import sys

from actx_lib import runner

_MAX_ENTRIES = 200
_ENTRY_LIMIT = _MAX_ENTRIES - 1  # reserve one output line for the truncation marker


def _ignored_file(name, patterns):
    return any(fnmatch.fnmatch(name, pattern) for pattern in patterns)


def _render(path, ignore_dirs, ignore_files):
    """Every line of the walk summary (uncapped)."""
    lines = []
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

        lines.append("%s%s (%d)" % ("  " * depth, label, len(files)))
        for name in files:
            lines.append("%s  %s" % ("  " * depth, name))
    return lines


def run(args, config):
    # Bare or single path -> the walk summary below; anything else (a flag,
    # two or more paths) -> the real tree binary with its own exit code
    # (TK-61; a missing binary is rc 127).
    if len(args) > 1 or (args and args[0].startswith("-")):
        return runner.run_lossless(["tree"] + args, config, strategy="tree")
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
        lines = _render(path, ignore_dirs, ignore_files)
        if len(lines) <= _ENTRY_LIMIT:
            print("\n".join(lines))
            return 0
        shown = lines[:_ENTRY_LIMIT]
        shown.append("... (%d more)" % (len(lines) - _ENTRY_LIMIT))
        # Entries omitted: the full walk stays recoverable (TK-61).
        full = subprocess.CompletedProcess(
            ["tree"] + args, 0, "\n".join(lines) + "\n", ""
        )
        runner.tee_listing(["tree"] + args, full, "\n".join(shown), config)
        return 0
    except OSError as exc:
        print("tree: %s" % exc, file=sys.stderr)
        return 1
