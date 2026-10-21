import os
import sys

import actx_lib.rewriter as rewriter

VERSION = "actx 2.13.2"

USAGE = """usage: actx [--raw] [--ultra-compact] [-v|-vv|-vvv] <command> [args...]

commands:
  git, ls, grep, find, wc, head, tail, sort, uniq, rg, cat, read, smart, tree
  pytest, cargo, go, jest, vitest, ruff, tsc, eslint, golangci-lint, next
  pip, uv, npm, pnpm, docker, kubectl, helm, gh, aws
  vercel, netlify, railway, wrangler, supabase, flyctl, gcloud
  run [--errors|--failures|--digest] <cmd...>
  gain [--graph|--history|--daily|--breakdown] [--format json]
  discover
  session
  insights [--days N] [--top N] [--verbose-commands] [--json]
  tracking [on|off|status|clear]
  rewrite "<command>"
  hook [--agent codex|opencode|devin|pi] [--payload <json>]
  init [--agent <name>|all] [--show] [--uninstall]

user-declared heads from the "custom_heads" list in
~/.config/actx/config.json behave like `actx run <head> ...`.
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


_BUILTIN_COMMANDS = frozenset({
    "rewrite", "run", "gain", "discover", "session", "insights",
    "hook", "init", "tracking",
})


def _has_class(head):
    """True when the bare head has an output class (fail open: False)."""
    try:
        return rewriter.output_class([head]) is not None
    except Exception:
        return False


# Reserved custom heads already warned about in this process.
_WARNED_RESERVED = set()


def _custom_head_requested(command, config, registry):
    """True when command is a user-declared custom head (TK-39).

    Validation: only a list of non-empty strings counts; names reserved for
    builtin commands, REGISTRY heads or heads with an output class (TK-61:
    cat/grep/... are dispatched by class before custom heads) are ignored
    with a stderr warning, at most once per process per head (they keep
    their native semantics). custom_heads never extends the §7
    rewriter whitelist - it only gives `actx <head> args` the semantics of
    `actx run <head> args`."""
    heads = config.get("custom_heads", [])
    if not isinstance(heads, list):
        return False
    for head in heads:
        if not isinstance(head, str) or not head:
            continue
        if head in _BUILTIN_COMMANDS or head in registry or _has_class(head):
            if head not in _WARNED_RESERVED:
                _WARNED_RESERVED.add(head)
                print(
                    "actx: ignoring reserved custom head: %s" % head,
                    file=sys.stderr,
                )
            continue
        if head == command:
            return True
    return False


def _run(args, raw):
    if not args:
        print("error: run requires a command", file=sys.stderr)
        return 1

    from actx_lib import config
    from actx_lib import runner
    from actx_lib import tracking

    mode, rest = _parse_run_args(args)
    if mode is None and rest is None:
        return 1

    cfg = config.load()
    tracking.set_enabled(tracking.configured_enabled(cfg))
    tracking.set_retention_days(tracking.configured_retention_days(cfg))

    if mode is None:
        if raw:
            return runner.run_passthrough(rest)
        if _bypass_requested(rest[0], cfg):
            return runner.run_passthrough(rest)
        return runner.run(rest, cfg)

    if not rest:
        print("error: run --%s requires a command" % mode, file=sys.stderr)
        return 1

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

    if command == "gain":
        try:
            from actx_lib import gain
        except ImportError:
            print("not implemented", file=sys.stderr)
            return 1
        return gain.main(args)

    if command in ("discover", "session", "insights"):
        try:
            from actx_lib import insights
        except ImportError:
            print("not implemented", file=sys.stderr)
            return 1
        if command == "discover":
            return insights.run_discover(args)
        if command == "insights":
            return insights.run_insights(args)
        return insights.run_session(args)

    if command == "hook":
        try:
            from actx_lib import hook
        except ImportError:
            print("not implemented", file=sys.stderr)
            return 1
        return hook.main(args)

    if command == "init":
        try:
            from actx_lib import installer
        except ImportError:
            print("not implemented", file=sys.stderr)
            return 1
        return installer.main(args)

    if command == "tracking":
        try:
            from actx_lib import tracking_cli
        except ImportError:
            print("not implemented", file=sys.stderr)
            return 1
        return tracking_cli.main(args)

    return _guarded_dispatch(command, args, raw, ultra)


def _discard_stdout():
    """After EPIPE: point fd 1 at /dev/null so the interpreter's exit-time
    flush of buffered output cannot fail a second time."""
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
    except (OSError, ValueError):
        pass


def _command_argv(command, args):
    """The user's command argv for the boundary's recovery spawn."""
    if command == "run":
        return _parse_run_args(args)[1] or None
    return [command] + args


def _guarded_dispatch(command, args, raw, ultra):
    """The one error boundary around every command-running path.

    BrokenPipe on stdout -> the command's exit code (141 when none ran);
    any other internal error -> one `[actx] internal error: <Type>` line,
    then runner.recover: a command not yet started is run once, a captured
    result is emitted once; a command is never started twice. Steps after
    printing are guarded where they run, so they never reach here.
    """
    from actx_lib import runner

    runner._STATE.reset()
    try:
        code = _dispatch_command(command, args, raw, ultra)
        sys.stdout.flush()
        return code
    except BrokenPipeError:
        _discard_stdout()
        result = runner._STATE.result
        return result.returncode if result is not None else 141
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        try:
            print("[actx] internal error: %s" % type(exc).__name__, file=sys.stderr)
            cmd = _command_argv(command, args)
            return runner.recover(cmd) if cmd else 1
        except Exception:
            return 1


def _dispatch_command(command, args, raw, ultra):
    if command == "run":
        return _run(args, raw)

    from actx_lib import config
    from actx_lib import runner
    from actx_lib import tracking

    cfg = config.load()
    tracking.set_enabled(tracking.configured_enabled(cfg))
    tracking.set_retention_days(tracking.configured_retention_days(cfg))

    if raw:
        return runner.run_passthrough([command] + args)
    if _bypass_requested(command, cfg):
        return runner.run_passthrough([command] + args)

    from actx_lib import cli_families
    from actx_lib.filters import REGISTRY

    # Output class (TK-61): content -> the command's bytes 1:1 (secret
    # values masked); log -> repeat collapse + ANSI strip, no cap;
    # summary -> the REGISTRY filter. Content/log and path-written summary
    # heads execute the original argv (head token included); a summary
    # head written as a path never reaches a REGISTRY filter (those
    # rebuild argv from a literal name). Fail open to the content path.
    argv = [command] + args
    try:
        head = cli_families.head_key(command)
        output = rewriter.output_class(argv)
    except Exception:
        return runner.run_content(argv, cfg)
    if output == "content":
        return runner.run_content(argv, cfg)
    if output == "log":
        return runner.run_lossless(argv, cfg, cap=False, stderr=True)
    if output == "summary":
        if command == head and command in REGISTRY:
            if ultra:
                cfg = dict(cfg)
                cfg["ultra_compact"] = True
            return REGISTRY[command](args, cfg)
        return runner.run_lossless(argv, cfg)

    # Order is fixed (TK-39): raw/bypass -> classes/REGISTRY ->
    # custom_heads -> unknown. cfg is already loaded above; calling
    # runner.run directly (not _run) avoids a second config load.
    # raw/bypass for custom heads are handled by the shared branches above.
    if _custom_head_requested(command, cfg, REGISTRY):
        return runner.run(argv, cfg)

    print("error: unknown command: %s" % command, file=sys.stderr)
    print("hint: run it through actx: actx run %s" % command, file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
