"""Mobile toolchain transport: flutter/dart/swift/swiftlint/swiftformat/
xcodebuild/xcrun/pod/gradlew (TK-42).

Exec-array execution plus profile-driven compaction through the
compact_profiles engine (test_runner_filter/linter_filter pattern):

- flutter/dart test          -> flutter_test/dart_test profiles (strategy "test")
- flutter/dart analyze       -> flutter_analyze/dart_analyze (strategy "lint")
- swiftlint lint             -> swiftlint (strategy "lint")
- swift build, xcodebuild
  with -scheme/-destination  -> xcodebuild (swiftc ``error:``/``warning:`` and
                                ``** BUILD`` verdict lines; strategy "mobile")
- informational RO output
  (doctor, pub outdated/deps, xcodebuild -list/-showsdks/…, simctl list,
  pod outdated/list, swiftformat --lint/--dryrun, swift test, gradlew)
                             -> runner.run_lossless generic compaction
- everything else            -> runner.run_passthrough (fail-open raw)

Fail-open: any compaction error reaches raw stdout+stderr with the original
exit code via runner.compacted_result / run_lossless contracts.
"""

from actx_lib import runner
from actx_lib.filters import compact_profiles

_SWIFTFORMAT_READONLY = ("--lint", "--dryrun", "--dry-run")
_XCODEBUILD_INFO_FLAGS = ("-list", "-showsdks", "-showBuildSettings")


def _test_compact(text, profile_name):
    data = compact_profiles.parse_test(text, compact_profiles.PROFILES[profile_name])
    parts = []
    if data["failures"].strip():
        parts.append(data["failures"])
    parts.append("%d failed, %d passed" % (data["failed"], data["passed"]))
    return "\n".join(parts)


def _run_test(cmd, config, profile_name):
    result = runner.execute(cmd)
    if result is None:
        return 1
    return runner.compacted_result(
        cmd,
        result,
        config,
        runner.stdout_compactor(lambda text: _test_compact(text, profile_name)),
        strategy="test",
    )


def _run_lint(cmd, config, profile_name, strategy="lint"):
    result = runner.execute(cmd)
    if result is None:
        return 1

    def parser(text):
        return compact_profiles.parse_lint(
            text, compact_profiles.PROFILES[profile_name]
        )

    return runner.compacted_result(
        cmd, result, config, runner.stdout_compactor(parser), strategy=strategy
    )


def _run_lossless(cmd, config):
    return runner.run_lossless(cmd, config, strategy="mobile")


def run_flutter(args, config):
    if not args:
        return runner.run_passthrough(["flutter"])
    sub = args[0]
    if sub == "test":
        return _run_test(["flutter"] + args, config, "flutter_test")
    if sub == "analyze":
        return _run_lint(["flutter"] + args, config, "flutter_analyze")
    if sub == "doctor":
        return _run_lossless(["flutter"] + args, config)
    if sub == "pub" and len(args) >= 2 and args[1] in ("outdated", "deps"):
        return _run_lossless(["flutter"] + args, config)
    return runner.run_passthrough(["flutter"] + args)


def run_dart(args, config):
    if not args:
        return runner.run_passthrough(["dart"])
    if args[0] == "test":
        return _run_test(["dart"] + args, config, "dart_test")
    if args[0] == "analyze":
        return _run_lint(["dart"] + args, config, "dart_analyze")
    return runner.run_passthrough(["dart"] + args)


def run_swift(args, config):
    if not args:
        return runner.run_passthrough(["swift"])
    if args[0] == "build":
        # SwiftPM emits swiftc-style error:/warning: diagnostics; the
        # xcodebuild profile covers that format class.
        return _run_lint(["swift"] + args, config, "xcodebuild", strategy="mobile")
    if args[0] == "test":
        # XCTest summaries carry no error:/warning: tokens - generic lossless
        # compaction instead, so failure counts are never distorted.
        return _run_lossless(["swift"] + args, config)
    return runner.run_passthrough(["swift"] + args)


def run_swiftlint(args, config):
    if args and args[0] == "lint":
        return _run_lint(["swiftlint"] + args, config, "swiftlint")
    return runner.run_passthrough(["swiftlint"] + args)


def run_swiftformat(args, config):
    if any(tok in _SWIFTFORMAT_READONLY for tok in args):
        return _run_lossless(["swiftformat"] + args, config)
    return runner.run_passthrough(["swiftformat"] + args)


def run_xcodebuild(args, config):
    cmd = ["xcodebuild"] + args
    if any(tok in _XCODEBUILD_INFO_FLAGS for tok in args):
        return _run_lossless(cmd, config)
    if "-scheme" in args or "-destination" in args:
        return _run_lint(cmd, config, "xcodebuild", strategy="mobile")
    return runner.run_passthrough(cmd)


def run_xcrun(args, config):
    if len(args) >= 2 and args[0] == "simctl" and args[1] == "list":
        return _run_lossless(["xcrun"] + args, config)
    return runner.run_passthrough(["xcrun"] + args)


def run_pod(args, config):
    if args and args[0] in ("outdated", "list"):
        return _run_lossless(["pod"] + args, config)
    return runner.run_passthrough(["pod"] + args)


def run_gradlew(args, config):
    return _run_lossless(["./gradlew"] + args, config)
