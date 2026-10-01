"""Listing summaries: ls/gls and find. The content heads (cat head tail
sort uniq wc rg grep) are runner.run_content paths (TK-61) and never reach
this module."""

import os

from actx_lib import runner

_FIND_PASSTHROUGH = {
    "-print0", "-printf", "-ls", "-delete", "-exec", "-execdir",
    "-ok", "-okdir", "-fprint", "-fprintf", "-fls",
}


_LS_FLAGS = {
    "-l", "-a", "-la", "-al", "-lh", "-lah", "-ahl", "-hal", "-hla", "-alh",
    "-1", "-F",
}


def run_ls(args, config, head="ls"):
    """`head` is the executed program (`gls`, Homebrew coreutils, shares
    this summary)."""
    if any(arg.startswith("-") for arg in args):
        if all(
            (arg in _LS_FLAGS) or (not arg.startswith("-"))
            for arg in args
        ) and sum(1 for arg in args if not arg.startswith("-")) <= 1:
            return runner.run_lossless([head] + args, config, strategy="ls")
        return runner.run_passthrough([head] + args)
    if len(args) > 1:
        return runner.run_passthrough([head] + args)
    cmd = [head, "-1"] + args
    result = runner.execute(cmd)
    if result is None:
        return 1
    if result.returncode != 0:
        return runner.run_passthrough([head] + args)

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
        remaining = 0
        if config.get("ultra_compact"):
            if len(entries) <= 30:
                shown = dirs + files
                remaining = 0
            else:
                shown = dirs[:10] + files[:10]
                remaining = len(entries) - len(shown)
            out = ["%s/ (%d): %s" % (display, len(entries), " ".join(shown))]
            if remaining:
                out.append("... (%d more)" % remaining)
        else:
            out = ["%s/ (%d)" % (display, len(entries))]
            if len(entries) <= 30:
                out.extend("  " + entry for entry in dirs + files)
            else:
                shown_dirs = dirs[:10]
                shown_files = files[:10]
                out.extend("  " + entry for entry in shown_dirs + shown_files)
                remaining = len(entries) - len(shown_dirs) - len(shown_files)
                out.append("  ... (%d more)" % remaining)
        text = "\n".join(out)
        extra = 0
        if remaining:
            # Entries omitted: the full listing stays recoverable (TK-61).
            tee_path = runner.tee_listing(cmd, result, text, config)
            extra = len("[full output: %s]\n" % tee_path) if tee_path else 0
        else:
            print(text)
        runner.record_compacted(cmd, result, text, "ls", extra_bytes=extra)
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
        # Partial results survive a failing exit (TK-61).
        runner.print_lossless_stdout(cmd, result, config)
        return result.returncode
    if len(result.stdout) <= 200:
        runner.print_raw(result)
        runner.record_raw(cmd, result, "find")
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
        omitted = total_dirs > 200
        for dirname, names in list(dirs.items())[:200]:
            names = sorted(set(names))
            out.append("%s (%d):" % (dirname, len(names)))
            out.extend("  " + name for name in names[:10])
            if len(names) > 10:
                out.append("  ... (%d more)" % (len(names) - 10))
                omitted = True
        if total_dirs > 200:
            out.append("... (%d more dirs)" % (total_dirs - 200))
        text = "\n".join(out)
        extra = 0
        if omitted:
            # Entries omitted: the full listing stays recoverable (TK-61).
            tee_path = runner.tee_listing(cmd, result, text, config)
            extra = len("[full output: %s]\n" % tee_path) if tee_path else 0
        elif out:
            print(text)
        runner.record_compacted(cmd, result, text, "find", extra_bytes=extra)
        return 0
    except Exception:
        return runner.raw_fallback(result)


def run_gls(args, config):
    return run_ls(args, config, head="gls")
