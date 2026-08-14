import sys

import actx_lib.rewriter as rewriter

VERSION = "actx 2.2"

FILTER_COMMANDS = {"git", "ls", "grep", "find", "read"}

USAGE = """usage: actx [--raw] [-v|-vv|-vvv] <command> [args...]

commands:
  git, ls, grep, find, read
  run <cmd...>
  rewrite "<command>"
  hook
  init [--agent <name>] [--show] [--uninstall]
"""


def _parse_global_flags(argv):
    """Return (command, args, verbosity, exit_code, raw). exit_code is None to continue."""
    verbosity = 0
    raw = False
    idx = 0
    while idx < len(argv):
        token = argv[idx]
        if token == "--version":
            print(VERSION)
            return None, None, verbosity, 0, raw
        if token in ("--help", "-h"):
            print(USAGE, end="")
            return None, None, verbosity, 0, raw
        if token == "--raw":
            raw = True
            idx += 1
            continue
        if token in ("-v", "-vv", "-vvv"):
            verbosity += token.count("v")
            idx += 1
            continue
        break
    if idx >= len(argv):
        print(USAGE, end="")
        return None, None, verbosity, 0, raw
    return argv[idx], argv[idx + 1 :], verbosity, None, raw


def main(argv):
    command, args, verbosity, exit_code, raw = _parse_global_flags(argv[1:])
    if exit_code is not None:
        return exit_code

    if command == "rewrite":
        if len(args) > 1:
            print("error: rewrite takes exactly one argument", file=sys.stderr)
            return 1
        command_arg = args[0] if args else ""
        rewritten = rewriter.rewrite(command_arg)
        if rewritten is not None:
            print(rewritten)
        return 0

    if command == "run":
        if not args:
            print("error: run requires a command", file=sys.stderr)
            return 1
        from actx_lib import config
        from actx_lib import runner

        if raw:
            return runner.run_passthrough(args)
        return runner.run(args, config.load())

    if command == "hook":
        try:
            from actx_lib import hook
        except ImportError:
            print("not implemented", file=sys.stderr)
            return 1
        return hook.main()

    if command == "init":
        try:
            from actx_lib import installer
        except ImportError:
            print("not implemented", file=sys.stderr)
            return 1
        return installer.main(args)

    if command in FILTER_COMMANDS:
        from actx_lib import config
        from actx_lib import runner

        if raw:
            return runner.run_passthrough([command] + args)
        from actx_lib.filters import REGISTRY

        return REGISTRY[command](args, config.load())

    print("error: unknown command: %s" % command, file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
