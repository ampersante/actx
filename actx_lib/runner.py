import hashlib
import json
import os
import subprocess
import sys
import time

from actx_lib import tracking, user_filter

_STREAM_LIMIT = 10 * 1024 * 1024


def _text_bytes(text):
    return len(text.encode("utf-8")) if text else 0


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


def _truncate_lines(text, max_lines, max_line_chars):
    if not text:
        return text
    lines = text.split("\n")
    truncated = False
    if len(lines) > max_lines:
        lines = lines[:max_lines]
        truncated = True
    out = [_truncate_line(line, max_line_chars) for line in lines]
    if truncated:
        out.append("...(truncated)")
    return "\n".join(out)


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
    tracking.record(cmd, cmd[0], raw_bytes, raw_bytes, result.returncode, passthrough=1)
    return result.returncode


def run(cmd, config):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
    except OSError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    truncate = config.get("truncate", {})
    max_lines = truncate.get("max_lines", 500)
    max_line_chars = truncate.get("max_line_chars", 300)

    truncated_stdout = _truncate_lines(result.stdout, max_lines, max_line_chars)
    truncated_stderr = _truncate_lines(result.stderr, max_lines, max_line_chars)

    rules = user_filter.load()
    if rules is None:
        rules = []
    if rules and result.returncode == 0 and truncated_stdout:
        try:
            truncated_stdout = user_filter.apply(rules, cmd[0], truncated_stdout)
        except Exception:
            return raw_fallback(result)

    raw_bytes = _text_bytes(result.stdout) + _text_bytes(result.stderr)
    if result.returncode == 0:
        if truncated_stdout:
            print(truncated_stdout, end="")
        if truncated_stderr:
            print(truncated_stderr, end="", file=sys.stderr)
        if result.stdout and not result.stdout.endswith("\n"):
            print()
        if result.stderr and not result.stderr.endswith("\n"):
            print(file=sys.stderr)
        emitted = _text_bytes(truncated_stdout) + _text_bytes(truncated_stderr)
        emitted += (
            1 if result.stdout and not result.stdout.endswith("\n") else 0
        )
        emitted += (
            1 if result.stderr and not result.stderr.endswith("\n") else 0
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

    tracking.record(cmd, cmd[0], raw_bytes, emitted, result.returncode)

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


def compacted_result(cmd, result, config, compact_fn, tee_policy="auto"):
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
        tracking.record(cmd, cmd[0], raw_bytes, emitted, result.returncode)
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
    tracking.record(cmd, cmd[0], raw_bytes, emitted, result.returncode)
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
    return "%s\n... (%d lines skipped)\n%s" % (head, skipped, tail)


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
    tracking.record(cmd, cmd[0], raw_bytes, emitted, result.returncode)
    return result.returncode
