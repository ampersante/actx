import sys

import actx_lib.rewriter as rewriter

VERSION = "actx 2.2.2"

USAGE = """usage: actx [--raw] [--ultra-compact] [-v|-vv|-vvv] <command> [args...]

commands:
  git, ls, grep, find, read, smart, tree
  pytest, cargo, go, jest, vitest, ruff, tsc, eslint, golangci-lint, next
  pip, uv, npm, pnpm, docker, kubectl, gh, aws
  run [--errors|--failures|--digest] <cmd...>
  gain [--graph|--history|--daily] [--format json]
  discover
  session
  rewrite "<command>"
  hook
  init [--agent <name>] [--show] [--uninstall]
"""


def _parse_global_flags(argv):
    """Return (command, args, verbosity, exit_code, raw, ultra_compact)."""
    verbosity = 0
    raw = False
    ultra = False
    idx = 0
    while idx < len(argv):
        token = argv[idx]
        if token == "--version":
            print(VERSION)
            return None, None, verbosity, 0, raw, ultra
        if token in ("--help", "-h"):
            print(USAGE, end="")
            return None, None, verbosity, 0, raw, ultra
        if token == "--raw":
            raw = True
            idx += 1
            continue
        if token == "--ultra-compact":
            ultra = True
            idx += 1
            continue
        if token in ("-v", "-vv", "-vvv"):
            verbosity += token.count("v")
            idx += 1
            continue
        break
    if idx >= len(argv):
        print(USAGE, end="")
        return None, None, verbosity, 0, raw, ultra
    return argv[idx], argv[idx + 1 :], verbosity, None, raw, ultra


def _bypass_requested(command, config):
    import os

    if os.environ.get("ACTX_BYPASS") == "1":
        return True
    bypass = config.get("bypass_commands", [])
    if not isinstance(bypass, list):
        return False
    return command in bypass


def _parse_run_args(args):
    """Return (mode, rest) where mode is None for generic run."""
    mode = None
    index = 0
    while index < len(args):
        token = args[index]
        if token in ("--errors", "--failures", "--digest"):
            if mode is not None:
                print("error: run flags are mutually exclusive", file=sys.stderr)
                return None, None
            mode = token[2:]
            index += 1
            continue
        break
    return mode, args[index:]


def _run(args, raw):
    if not args:
        print("error: run requires a command", file=sys.stderr)
        return 1

    from actx_lib import config
    from actx_lib import runner

    mode, rest = _parse_run_args(args)
    if mode is None and rest is None:
        return 1

    if mode is None:
        if raw:
            return runner.run_passthrough(rest)
        cfg = config.load()
        if _bypass_requested(rest[0], cfg):
            return runner.run_passthrough(rest)
        return runner.run(rest, cfg)

    if not rest:
        print("error: run --%s requires a command" % mode, file=sys.stderr)
        return 1

    cfg = config.load()
    if _bypass_requested(rest[0], cfg):
        return runner.run_passthrough(rest)

    if mode == "errors":
        return runner.run_errors(rest)
    if mode == "digest":
        return runner.run_digest(rest)

    from actx_lib.filters import test_runner_filter

    tool = test_runner_filter.detect(rest)
    if tool is None:
        return runner.run_passthrough(rest)
    return test_runner_filter.run_failures(rest, cfg)


def main(argv):
    command, args, verbosity, exit_code, raw, ultra = _parse_global_flags(argv[1:])
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
        return _run(args, raw)

    if command == "gain":
        try:
            from actx_lib import gain
        except ImportError:
            print("not implemented", file=sys.stderr)
            return 1
        return gain.main(args)

    if command in ("discover", "session"):
        try:
            from actx_lib import insights
        except ImportError:
            print("not implemented", file=sys.stderr)
            return 1
        if command == "discover":
            return insights.run_discover(args)
        return insights.run_session(args)

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

    from actx_lib import config
    from actx_lib import runner

    if raw:
        return runner.run_passthrough([command] + args)
    cfg = config.load()
    if _bypass_requested(command, cfg):
        return runner.run_passthrough([command] + args)

    from actx_lib.filters import REGISTRY

    if command in REGISTRY:
        if ultra:
            cfg = dict(cfg)
            cfg["ultra_compact"] = True
        return REGISTRY[command](args, cfg)

    print("error: unknown command: %s" % command, file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
