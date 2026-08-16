import hashlib
import json
import os
import re
import subprocess
import sys
import time

from actx_lib import tracking, user_filter

_STREAM_LIMIT = 10 * 1024 * 1024


def _text_bytes(text):
    return len(text.encode("utf-8")) if text else 0


def record_raw(cmd, result, strategy, passthrough=0):
    raw = _text_bytes(result.stdout) + _text_bytes(result.stderr)
    tracking.record(
        cmd, cmd[0], raw, raw, result.returncode,
        passthrough=passthrough, strategy=strategy,
    )


def record_compacted(cmd, result, out_text, strategy, newline=True, extra_bytes=0):
    raw = _text_bytes(result.stdout) + _text_bytes(result.stderr)
    emitted = _text_bytes(out_text) + extra_bytes
    if newline and out_text and not out_text.endswith("\n"):
        emitted += 1
    tracking.record(
        cmd, cmd[0], raw, emitted, result.returncode, strategy=strategy,
    )


def _tee_min_bytes(config):
    tee = config.get("tee", {})
    try:
        return int(tee.get("min_bytes", 0))
    except (TypeError, ValueError):
        return 0


def _join_cmd(cmd):
    return " ".join(cmd)


def _truncate_line(line, max_chars):
    if len(line) <= max_chars:
        return line
    return line[:max_chars] + "...(truncated)"


_ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def _strip_ansi(text):
    if not text:
        return text
    return _ANSI_RE.sub("", text)


def _collapse_lines(text):
    """Collapse consecutive identical non-empty lines losslessly."""
    if not text:
        return text
    lines = text.split("\n")
    had_trailing_newline = lines[-1] == ""
    if had_trailing_newline:
        lines = lines[:-1]
    out = []
    i = 0
    while i < len(lines):
        line = lines[i]
        j = i + 1
        while j < len(lines) and lines[j] == line:
            j += 1
        count = j - i
        if count > 1 and line != "":
            out.append("%s  [×%d]" % (line, count))
        else:
            out.extend([line] * count)
        i = j
    return "\n".join(out) + ("\n" if had_trailing_newline else "")


def _lossless_transform(text):
    return _collapse_lines(_strip_ansi(text))


def _cap_lines_explicit(text, max_lines, max_line_chars):
    """Head+tail with an explicit count marker when the cap is exceeded."""
    if not text:
        return text
    lines = text.split("\n")
    had_trailing_newline = lines[-1] == ""
    if had_trailing_newline:
        lines = lines[:-1]
    lines = [_truncate_line(line, max_line_chars) for line in lines]
    if len(lines) <= max_lines:
        return "\n".join(lines) + ("\n" if had_trailing_newline else "")
    max_lines = max(1, max_lines)
    head_count = max_lines // 2
    tail_count = max_lines - head_count
    head = lines[:head_count]
    tail = lines[-tail_count:]
    omitted = len(lines) - max_lines
    marker = "...[truncated: %d lines omitted — сузьте команду]" % omitted
    return (
        "\n".join(head + [marker] + tail)
        + ("\n" if had_trailing_newline else "")
    )


def _print_transformed(stdout, stderr):
    if stdout:
        sys.stdout.write(stdout)
        if not stdout.endswith("\n"):
            sys.stdout.write("\n")
    if stderr:
        sys.stderr.write(stderr)
        if not stderr.endswith("\n"):
            sys.stderr.write("\n")


def _write_tee(cmd, stdout, stderr, exit_code, tee_dir):
    tee_dir = os.path.expanduser(tee_dir)
    os.makedirs(tee_dir, exist_ok=True)
    command_hash = hashlib.sha1(_join_cmd(cmd).encode("utf-8")).hexdigest()
    timestamp = int(time.time())
    name = "%d_%s.log" % (timestamp, command_hash[:8])

    def cap_stream(text):
        data = text.encode("utf-8")
        if len(data) <= _STREAM_LIMIT:
            return text
        cut = data[:_STREAM_LIMIT]
        while True:
            try:
                return cut.decode("utf-8") + "...(truncated)"
            except UnicodeDecodeError:
                cut = cut[:-1]

    record = {
        "command": command_hash,
        "stdout": cap_stream(stdout),
        "stderr": cap_stream(stderr),
        "exit_code": exit_code,
    }
    path = os.path.join(tee_dir, name)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(record, handle)
    _retain(tee_dir)
    return path


def _retain(tee_dir):
    try:
        names = [n for n in os.listdir(tee_dir) if n.endswith(".log")]
    except OSError:
        return
    if len(names) <= 100:
        return
    paths = [os.path.join(tee_dir, n) for n in names]
    paths.sort(key=lambda p: os.path.getmtime(p))
    for path in paths[: len(paths) - 100]:
        try:
            os.remove(path)
        except OSError:
            pass


def run_passthrough(cmd):
    """Execute without filtering; bytes mode preserves non-UTF-8 output."""
    try:
        result = subprocess.run(cmd, capture_output=True)
    except OSError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    if result.stdout:
        sys.stdout.buffer.write(result.stdout)
        sys.stdout.buffer.flush()
    if result.stderr:
        sys.stderr.buffer.write(result.stderr)
        sys.stderr.buffer.flush()
    raw_bytes = len(result.stdout) + len(result.stderr)
    tracking.record(
        cmd, cmd[0], raw_bytes, raw_bytes, result.returncode,
        passthrough=1, strategy="passthrough",
    )
    return result.returncode


def run_lossless(cmd, config):
    """Execute and apply lossless transforms; fail open on any error."""
    result = execute(cmd)
    if result is None:
        return 1
    try:
        truncate = config.get("truncate", {})
        max_lines = truncate.get("max_lines", 500)
        max_line_chars = truncate.get("max_line_chars", 300)
        stdout = _cap_lines_explicit(
            _lossless_transform(result.stdout), max_lines, max_line_chars
        )
        stderr = _cap_lines_explicit(
            _lossless_transform(result.stderr), max_lines, max_line_chars
        )
        _print_transformed(stdout, stderr)
        raw_bytes = _text_bytes(result.stdout) + _text_bytes(result.stderr)
        emitted = _text_bytes(stdout) + _text_bytes(stderr)
        tracking.record(
            cmd, cmd[0], raw_bytes, emitted, result.returncode,
            strategy="lossless",
        )
        if tee_decision(config, "auto", result.returncode):
            write_tee(cmd, result, config)
        return result.returncode
    except Exception:
        return raw_fallback(result)


def run(cmd, config):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
    except OSError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    truncate = config.get("truncate", {})
    max_lines = truncate.get("max_lines", 500)
    max_line_chars = truncate.get("max_line_chars", 300)

    raw_stdout = result.stdout
    rules = user_filter.load()
    if rules is None:
        rules = []
    if rules and result.returncode == 0 and raw_stdout:
        try:
            raw_stdout = user_filter.apply(rules, cmd[0], raw_stdout)
        except Exception:
            return raw_fallback(result)

    stdout_compacted = _cap_lines_explicit(
        _lossless_transform(raw_stdout), max_lines, max_line_chars
    )
    stderr_compacted = _cap_lines_explicit(
        _lossless_transform(result.stderr), max_lines, max_line_chars
    )

    raw_bytes = _text_bytes(result.stdout) + _text_bytes(result.stderr)
    if result.returncode == 0:
        if stdout_compacted:
            print(stdout_compacted, end="")
        if stderr_compacted:
            print(stderr_compacted, end="", file=sys.stderr)
        if stdout_compacted and not stdout_compacted.endswith("\n"):
            print()
        if stderr_compacted and not stderr_compacted.endswith("\n"):
            print(file=sys.stderr)
        emitted = _text_bytes(stdout_compacted) + _text_bytes(stderr_compacted)
        emitted += (
            1 if stdout_compacted and not stdout_compacted.endswith("\n") else 0
        )
        emitted += (
            1 if stderr_compacted and not stderr_compacted.endswith("\n") else 0
        )
    else:
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)
            if not result.stderr.endswith("\n"):
                print(file=sys.stderr)
        print("[exit: %d]" % result.returncode, file=sys.stderr)
        emitted = _text_bytes(result.stderr)
        emitted += 1 if result.stderr and not result.stderr.endswith("\n") else 0
        emitted += _text_bytes("[exit: %d]\n" % result.returncode)

    tracking.record(cmd, cmd[0], raw_bytes, emitted, result.returncode, strategy="generic")

    tee_config = config.get("tee", {})
    should_tee = bool(tee_config.get("enabled")) and (
        tee_config.get("mode") == "always"
        or (tee_config.get("mode") == "failures" and result.returncode != 0)
    )
    if should_tee and raw_bytes < _tee_min_bytes(config):
        should_tee = False

    if should_tee:
        path = _write_tee(
            cmd,
            result.stdout,
            result.stderr,
            result.returncode,
            tee_config.get("dir", "~/.local/share/actx/tee"),
        )
        print("[full output: %s]" % path, file=sys.stderr)

    return result.returncode


def execute(cmd):
    """Execute an exec-array, returning CompletedProcess or None on OSError."""
    try:
        return subprocess.run(cmd, capture_output=True, text=True)
    except OSError as exc:
        print(str(exc), file=sys.stderr)
        return None


def print_raw(result):
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)


def raw_fallback(result):
    print_raw(result)
    return result.returncode


def tee_decision(config, tee_policy, returncode, grep_no_match=False):
    if grep_no_match:
        return False
    if tee_policy == "always":
        return True
    tee = config.get("tee", {})
    if not tee.get("enabled"):
        return False
    mode = tee.get("mode", "failures")
    if mode == "always":
        return True
    if mode == "failures" and returncode != 0:
        return True
    return False


def write_tee(cmd, result, config):
    if _text_bytes(result.stdout) + _text_bytes(result.stderr) < _tee_min_bytes(config):
        return None
    tee = config.get("tee", {})
    path = _write_tee(
        cmd,
        result.stdout,
        result.stderr,
        result.returncode,
        tee.get("dir", "~/.local/share/actx/tee"),
    )
    print("[full output: %s]" % path, file=sys.stderr)
    return path


def compacted_result(cmd, result, config, compact_fn, tee_policy="auto", strategy="compact"):
    """Compact stdout for any exit code; fall back to raw output on error."""
    if result is None:
        return 1
    try:
        out = compact_fn(result)
        if out is None:
            return raw_fallback(result)
        rules = user_filter.load()
        if rules is None:
            rules = []
        if rules and out:
            out = user_filter.apply(rules, cmd[0], out)
        if out:
            print(out, end="")
            if not out.endswith("\n"):
                print()
        emitted = _text_bytes(out) + (1 if out and not out.endswith("\n") else 0)
        raw_bytes = _text_bytes(result.stdout) + _text_bytes(result.stderr)
        tracking.record(cmd, cmd[0], raw_bytes, emitted, result.returncode, strategy=strategy)
        if tee_decision(config, tee_policy, result.returncode):
            write_tee(cmd, result, config)
        return result.returncode
    except Exception:
        return raw_fallback(result)


def stdout_compactor(parser):
    """Adapt a text parser to compacted_result's CompletedProcess input."""

    def compact(result):
        if not result.stdout:
            return None
        return parser(result.stdout)

    return compact


def run_errors(cmd):
    result = execute(cmd)
    if result is None:
        return 1
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
        if not result.stderr.endswith("\n"):
            print(file=sys.stderr)
    raw_bytes = _text_bytes(result.stdout) + _text_bytes(result.stderr)
    emitted = _text_bytes(result.stderr)
    emitted += 1 if result.stderr and not result.stderr.endswith("\n") else 0
    tracking.record(cmd, cmd[0], raw_bytes, emitted, result.returncode, strategy="errors")
    return result.returncode


def _split_lines(text):
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines = lines[:-1]
    return lines


def digest_text(text, n=10):
    lines = _split_lines(text)
    if len(lines) <= 2 * n:
        return text
    head = "\n".join(lines[:n])
    tail = "\n".join(lines[-n:])
    skipped = len(lines) - 2 * n
    return "%s\n... (%d lines skipped — сузьте команду)\n%s" % (head, skipped, tail)


def run_digest(cmd, n=10):
    result = execute(cmd)
    if result is None:
        return 1
    if result.stdout:
        out = digest_text(result.stdout, n)
        print(out, end="")
        if not out.endswith("\n"):
            print()
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
        if not result.stderr.endswith("\n"):
            print(file=sys.stderr)
    emitted = _text_bytes(out) if result.stdout else 0
    emitted += 1 if result.stdout and not out.endswith("\n") else 0
    emitted += _text_bytes(result.stderr)
    emitted += 1 if result.stderr and not result.stderr.endswith("\n") else 0
    raw_bytes = _text_bytes(result.stdout) + _text_bytes(result.stderr)
    tracking.record(cmd, cmd[0], raw_bytes, emitted, result.returncode, strategy="digest")
    return result.returncode
