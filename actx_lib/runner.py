import hashlib
import json
import os
import re
import subprocess
import sys
import time

from actx_lib import hang_policy, redaction, tracking, user_filter

_STREAM_LIMIT = 10 * 1024 * 1024

_TEE_DIR = "~/.local/share/actx/tee"

# actx-internal refusal (streaming/interactive command).
NEVER_WRAP_EXIT_CODE = 125
# actx-internal timeout (subprocess.TimeoutExpired).
TIMEOUT_EXIT_CODE = 124


def _timeout_seconds(config, timeout_class):
    """Configured seconds for "default"/"generous"; defaults on bad values."""
    defaults = {"default": 600, "generous": 1800}
    value = (config.get("timeouts") or {}).get(
        "%s_s" % timeout_class, defaults[timeout_class]
    )
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        return defaults[timeout_class]
    if seconds <= 0:
        return defaults[timeout_class]
    return seconds


def _refused(cmd, code, passthrough=False):
    print(
        "[actx] streaming/interactive command refused — выполнить вручную: %s"
        % _join_cmd(cmd),
        file=sys.stderr,
    )
    if passthrough:
        tracking.record(
            cmd, cmd[0], 0, 0, code, passthrough=1, strategy="passthrough",
        )
    return code


def _synthetic_result(cmd, code, message):
    # actx_synthetic marks refusal/timeout results (TK-47): their stderr is
    # actx's own text, not command output, so it never feeds hint matching.
    result = subprocess.CompletedProcess(
        args=cmd, returncode=code, stdout="", stderr=message
    )
    result.actx_synthetic = True
    return result


def _timed_out(cmd, seconds, passthrough=False):
    print(_timed_out_message(cmd, seconds), file=sys.stderr)
    if passthrough:
        tracking.record(
            cmd, cmd[0], 0, 0, TIMEOUT_EXIT_CODE,
            passthrough=1, strategy="passthrough",
        )
    return TIMEOUT_EXIT_CODE


def _timed_out_message(cmd, seconds):
    return "[actx] command timed out after %gs — сузьте команду или выполните вручную: %s" % (
        seconds, _join_cmd(cmd),
    )


def _text_bytes(text):
    return len(text.encode("utf-8")) if text else 0


def _redact_result(result):
    """Masked view of a text CompletedProcess; None when redaction failed.

    Masking covers the screen (print/cap/tracking decisions) and the tee via
    _write_tee, so raw output never reaches disk on the happy path.
    """
    try:
        return subprocess.CompletedProcess(
            args=result.args,
            returncode=result.returncode,
            stdout=redaction.redact_text(result.stdout),
            stderr=redaction.redact_text(result.stderr),
        )
    except Exception:
        return None


def _secret_bearing_result(result):
    """True when stdout+stderr look secret-bearing; bytes decode lossily."""
    try:
        stdout = result.stdout
        stderr = result.stderr
        if isinstance(stdout, (bytes, bytearray)):
            stdout = bytes(stdout).decode("utf-8", "replace")
        if isinstance(stderr, (bytes, bytearray)):
            stderr = bytes(stderr).decode("utf-8", "replace")
        return redaction.secret_bearing((stdout or "") + (stderr or ""))
    except Exception:
        return True


def record_raw(cmd, result, strategy, passthrough=0):
    raw = _text_bytes(result.stdout) + _text_bytes(result.stderr)
    tracking.record(
        cmd, cmd[0], raw, raw, result.returncode,
        passthrough=passthrough, strategy=strategy,
        store_text=not _secret_bearing_result(result),
    )


def record_compacted(cmd, result, out_text, strategy, newline=True, extra_bytes=0):
    raw = _text_bytes(result.stdout) + _text_bytes(result.stderr)
    emitted = _text_bytes(out_text) + extra_bytes
    if newline and out_text and not out_text.endswith("\n"):
        emitted += 1
    tracking.record(
        cmd, cmd[0], raw, emitted, result.returncode, strategy=strategy,
        store_text=not _secret_bearing_result(result),
    )


def _tee_min_bytes(config):
    tee = config.get("tee", {})
    try:
        return int(tee.get("min_bytes", 0))
    except (TypeError, ValueError):
        return 0


def _join_cmd(cmd):
    return " ".join(cmd)


def _load_config():
    """Fresh config for paths that receive no config from their caller."""
    try:
        from actx_lib import config

        return config.load()
    except Exception:
        return {}


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


def _cap_lines_explicit(text, max_lines, max_line_chars, tee_path=None):
    """Head+tail with an explicit count marker when the cap is exceeded.

    tee_path (the forced tee of the uncut output) is named in the marker.
    """
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
    if tee_path:
        marker = "...[truncated: %d lines omitted — full output: %s]" % (
            omitted, tee_path,
        )
    else:
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


def _truncate_limits(config):
    truncate = config.get("truncate", {})
    return truncate.get("max_lines", 500), truncate.get("max_line_chars", 300)


def _is_json(text):
    """JSON predicate only (TK-61): valid JSON is printed as its masked raw
    text — never re-serialised, never capped, so no member is lost."""
    if not text or not text.strip():
        return False
    try:
        json.loads(text)
    except (ValueError, RecursionError):
        return False
    return True


def _lossless_streams(cmd, result, config, streams, cap=True):
    """The run_lossless form of each (raw, shown) stream pair.

    shown is the masked text to print; raw decides the JSON predicate.
    Non-JSON text gets ANSI strip + repeat collapse and, with cap, the
    explicit line/char cap. Any cut (line count or per-line char clip)
    forces a tee of the whole result regardless of tee.enabled/mode and
    the marker names its path. Returns (texts, cut, tee_path).
    """
    max_lines, max_line_chars = _truncate_limits(config)
    forms = []
    for raw, shown in streams:
        if _is_json(raw):
            forms.append((shown, False))
        else:
            forms.append((_lossless_transform(shown), cap))
    texts = [
        _cap_lines_explicit(text, max_lines, max_line_chars) if capped else text
        for text, capped in forms
    ]
    cut = any(text != form for text, (form, _) in zip(texts, forms))
    path = _tee_file(cmd, result, config) if cut else None
    if path:
        texts = [
            _cap_lines_explicit(form, max_lines, max_line_chars, path)
            if capped else form
            for form, capped in forms
        ]
    return texts, cut, path


def _finish_tee(cmd, result, config, cut, path, tee_policy="auto"):
    """Print the forced tee path of a cut; otherwise tee per tee_policy.

    A synthetic result (exec failure, refusal, timeout) holds only actx's
    own message: nothing to recover, no tee.
    """
    if getattr(result, "actx_synthetic", False):
        return
    if cut:
        if path:
            print("[full output: %s]" % path, file=sys.stderr)
        return
    if tee_decision(config, tee_policy, result.returncode):
        write_tee(cmd, result, config)


def _write_tee(cmd, stdout, stderr, exit_code, tee_dir):
    # The tee's redaction layer: callers pass the raw streams, so the
    # record's stdout is redact_text(raw stdout) exactly (PRD.md 9 format).
    # A redaction failure here means the raw output must not hit disk —
    # skip the file entirely.
    try:
        stdout = redaction.redact_text(stdout)
        stderr = redaction.redact_text(stderr)
    except Exception:
        return None
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


_HINT_AUTH = "[actx] hint: auth error — запустите login вручную (интерактивно; actx не исполняет его)"
_HINT_RATE = "[actx] hint: rate limit — повторите с паузой"

# TK-47 long-session heuristics: case-insensitive stderr substrings, only
# contextual forms — bare "401"/"429" stay out (false positives on failing
# test output; PRD.md plan 2026-09-07 A2). Patterns are lowered once here
# because the matcher lowercases stderr first: an all-caps stderr form
# ("HTTP 401 UNAUTHORIZED") must match too.
_HINT_PATTERNS = tuple(
    (tuple(pattern.lower() for pattern in patterns), hint)
    for patterns, hint in (
        (
            (
                "not logged in", "login required", "authentication required",
                "re-authenticate", "unauthorized", "HTTP 401",
                "401 Unauthorized", "status 401",
            ),
            _HINT_AUTH,
        ),
        (
            (
                "rate limit", "rate_limit", "too many requests",
                "quota exceeded", "HTTP 429", "429 Too Many",
            ),
            _HINT_RATE,
        ),
    )
)


def _session_hints(result):
    """Advisory hints for auth/rate-limit stderr on a failing exit code.

    Pure function: [] on exit 0, one hint per class at most; bytes stderr
    (run_passthrough path) decodes lossily.
    """
    if result.returncode == 0:
        return []
    if getattr(result, "actx_synthetic", False):
        return []
    try:
        stderr = result.stderr
        if isinstance(stderr, (bytes, bytearray)):
            stderr = bytes(stderr).decode("utf-8", "replace")
        stderr = (stderr or "").lower()
        return [
            hint
            for patterns, hint in _HINT_PATTERNS
            if any(p in stderr for p in patterns)
        ]
    except Exception:
        return []


def run_passthrough(cmd):
    """Execute without filtering; bytes mode preserves non-UTF-8 output."""
    try:
        timeout_class = hang_policy.classify(cmd)
    except Exception:
        timeout_class = "default"
    if timeout_class == "never_wrap":
        return _refused(cmd, NEVER_WRAP_EXIT_CODE, passthrough=True)

    timeout = _timeout_seconds(_load_config(), timeout_class)
    try:
        result = subprocess.run(cmd, capture_output=True, stdin=subprocess.DEVNULL, timeout=timeout)
    except subprocess.TimeoutExpired:
        return _timed_out(cmd, timeout, passthrough=True)
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
        store_text=not _secret_bearing_result(result),
    )
    try:
        for hint in _session_hints(result):
            print(hint, file=sys.stderr)
    except Exception:
        pass
    return result.returncode


def _exec_failure(cmd, exc):
    """Shell-style (exit code, message) for an exec failure (TK-61).

    One mapping for run_content and run_lossless: a missing program is 127,
    a program that cannot be executed is 126 — not execute()'s None -> 1.
    """
    head = cmd[0] if cmd else ""
    if isinstance(exc, FileNotFoundError):
        return 127, "%s: command not found" % head
    if isinstance(exc, PermissionError):
        return 126, "%s: Permission denied" % head
    return 126, "%s: %s" % (head, exc.strerror or exc)


def _mask_bytes(data):
    """redact_text over bytes: surrogateescape keeps every undecodable byte,
    so unmasked output round-trips byte-identical."""
    if not data:
        return data
    text = data.decode("utf-8", "surrogateescape")
    return redaction.redact_text(text).encode("utf-8", "surrogateescape")


def run_content(cmd, config):
    """Content class (TK-61): the command's own bytes, secret values masked.

    Bytes mode like run_passthrough; no ANSI strip, collapse, cap,
    re-serialisation or session hints, so the output is byte-identical to
    the raw command unless a secret value was masked. Exit code preserved.
    """
    try:
        timeout_class = hang_policy.classify(cmd)
    except Exception:
        timeout_class = "default"
    if timeout_class == "never_wrap":
        return _refused(cmd, NEVER_WRAP_EXIT_CODE, passthrough=True)

    timeout = _timeout_seconds(config, timeout_class)
    try:
        result = subprocess.run(
            cmd, capture_output=True, stdin=subprocess.DEVNULL, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        return _timed_out(cmd, timeout, passthrough=True)
    except OSError as exc:
        code, message = _exec_failure(cmd, exc)
        print(message, file=sys.stderr)
        return code
    try:
        stdout = _mask_bytes(result.stdout)
        stderr = _mask_bytes(result.stderr)
    except Exception:
        # Fail open: the agent needs the output (redact_text itself fails
        # open the same way).
        stdout, stderr = result.stdout, result.stderr
    sys.stdout.flush()
    sys.stderr.flush()
    if stdout:
        sys.stdout.buffer.write(stdout)
        sys.stdout.buffer.flush()
    if stderr:
        sys.stderr.buffer.write(stderr)
        sys.stderr.buffer.flush()
    tracking.record(
        cmd, cmd[0],
        len(result.stdout or b"") + len(result.stderr or b""),
        len(stdout or b"") + len(stderr or b""),
        result.returncode, strategy="content",
        store_text=not _secret_bearing_result(result),
    )
    return result.returncode


def run_lossless(cmd, config, strategy="lossless", cap=True, stderr=True):
    """Execute and print the run_lossless form; fail open on any error.

    Form: ANSI strip, repeat collapse with a `  [×N]` count, secret values
    masked, and with cap=True the explicit line/char cap (a cut forces a
    tee whose path the marker names); JSON is printed as its masked raw
    text. cap=False, stderr=True is the log class; stderr=False leaves
    stderr off the screen (the tee keeps it). An exec failure maps like a
    shell (127/126).
    """
    result = execute(cmd, shell_codes=True)
    if result is None:
        return 1
    try:
        streams = [(result.stdout or "", redaction.redact_text(result.stdout or ""))]
        if stderr:
            raw_err = result.stderr or ""
            streams.append((raw_err, redaction.redact_text(raw_err)))
        texts, cut, path = _lossless_streams(cmd, result, config, streams, cap)
        out_text = texts[0]
        err_text = texts[1] if stderr else ""
        _print_transformed(out_text, err_text)
        raw_bytes = _text_bytes(result.stdout) + _text_bytes(result.stderr)
        emitted = _text_bytes(out_text) + _text_bytes(err_text)
        tracking.record(
            cmd, cmd[0], raw_bytes, emitted, result.returncode,
            strategy=strategy,
            store_text=not _secret_bearing_result(result),
        )
        _finish_tee(cmd, result, config, cut, path)
        try:
            for hint in _session_hints(result):
                print(hint, file=sys.stderr)
        except Exception:
            pass
        return result.returncode
    except Exception:
        return raw_fallback(result)


def run(cmd, config):
    try:
        timeout_class = hang_policy.classify(cmd)
    except Exception:
        timeout_class = "default"
    if timeout_class == "never_wrap":
        return _refused(cmd, NEVER_WRAP_EXIT_CODE)

    timeout = _timeout_seconds(config, timeout_class)
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            stdin=subprocess.DEVNULL, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        print(_timed_out_message(cmd, timeout), file=sys.stderr)
        return TIMEOUT_EXIT_CODE
    except OSError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    try:
        combined = (result.stdout or "") + (result.stderr or "")
        if hang_policy.is_interactive_prompt(combined):
            print(
                "[actx] интерактивная команда — выполнить вручную: %s"
                % _join_cmd(cmd),
                file=sys.stderr,
            )
    except Exception:
        pass

    # Fail-open contract: if redaction fails, print RAW output (the agent
    # needs it), write no tee file and keep the command out of history.
    masked = _redact_result(result)
    if masked is None:
        print_raw(result)
        tracking.record(
            cmd, cmd[0], 0, 0, result.returncode, strategy="generic",
            store_text=False,
        )
        return result.returncode
    raw_stdout = masked.stdout

    rules = user_filter.load()
    if rules is None:
        rules = []
    if rules and result.returncode == 0 and raw_stdout:
        try:
            raw_stdout = user_filter.apply(rules, cmd[0], raw_stdout)
        except Exception:
            return raw_fallback(result)

    # stdout survives any exit code in the run_lossless form (JSON: masked
    # raw text); stderr is capped on success and whole on failure.
    ok = result.returncode == 0
    streams = [(result.stdout or "", raw_stdout or "")]
    if ok:
        streams.append((result.stderr or "", masked.stderr or ""))
    texts, cut, path = _lossless_streams(cmd, result, config, streams)
    stdout_out = texts[0]
    stderr_out = texts[1] if ok else (masked.stderr or "")

    raw_bytes = _text_bytes(result.stdout) + _text_bytes(result.stderr)
    emitted = 0
    for text, stream in ((stdout_out, sys.stdout), (stderr_out, sys.stderr)):
        if text:
            print(text, end="", file=stream)
            emitted += _text_bytes(text)
            if not text.endswith("\n"):
                print(file=stream)
                emitted += 1
    if not ok:
        print("[exit: %d]" % result.returncode, file=sys.stderr)
        emitted += _text_bytes("[exit: %d]\n" % result.returncode)

    tracking.record(
        cmd, cmd[0], raw_bytes, emitted, result.returncode, strategy="generic",
        store_text=not _secret_bearing_result(result),
    )
    _finish_tee(cmd, result, config, cut, path)

    try:
        for hint in _session_hints(result):
            print(hint, file=sys.stderr)
    except Exception:
        pass
    return result.returncode


def execute(cmd, shell_codes=False):
    """Execute an exec-array, returning CompletedProcess or None on OSError.

    shell_codes=True maps an exec failure like a shell instead
    (_exec_failure: 127/126) and returns it as a synthetic result.
    """
    try:
        timeout_class = hang_policy.classify(cmd)
    except Exception:
        timeout_class = "default"
    if timeout_class == "never_wrap":
        return _synthetic_result(
            cmd,
            NEVER_WRAP_EXIT_CODE,
            "[actx] streaming/interactive command refused — выполнить вручную: %s"
            % _join_cmd(cmd),
        )

    timeout = _timeout_seconds(_load_config(), timeout_class)
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True,
            stdin=subprocess.DEVNULL, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return _synthetic_result(cmd, TIMEOUT_EXIT_CODE, _timed_out_message(cmd, timeout))
    except OSError as exc:
        if shell_codes:
            code, message = _exec_failure(cmd, exc)
            return _synthetic_result(cmd, code, message)
        print(str(exc), file=sys.stderr)
        return None


def _masked_or_raw(text):
    """redact_text(text); the text itself when masking fails (fail open)."""
    try:
        return redaction.redact_text(text)
    except Exception:
        return text


def print_raw(result):
    """The result's own text with secret values masked (TK-61: the fallback
    of a failed or empty compactor never prints a secret value); every other
    byte as the command wrote it."""
    if result.stdout:
        print(_masked_or_raw(result.stdout), end="")
    if result.stderr:
        print(_masked_or_raw(result.stderr), end="", file=sys.stderr)


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


def _tee_file(cmd, result, config):
    """Write the tee record of the raw result; the path, or None.

    No policy check here (forced tees call it directly). A write failure
    prints one stderr warning and never raises, so no caller falls back to
    printing its output a second time.
    """
    tee = config.get("tee", {})
    try:
        return _write_tee(
            cmd,
            result.stdout or "",
            result.stderr or "",
            result.returncode,
            tee.get("dir", _TEE_DIR),
        )
    except Exception as exc:
        print("[actx] tee write failed: %s" % exc, file=sys.stderr)
        return None


def write_tee(cmd, result, config):
    if _text_bytes(result.stdout) + _text_bytes(result.stderr) < _tee_min_bytes(config):
        return None
    path = _tee_file(cmd, result, config)
    if path:
        print("[full output: %s]" % path, file=sys.stderr)
    return path


def tee_listing(cmd, raw, shown, config):
    """Print a listing summary that omits entries, then the path of a
    forced tee holding the full raw result (TK-61), regardless of
    tee.enabled/mode/min_bytes. Returns the path, or None."""
    print(shown)
    path = _tee_file(cmd, raw, config)
    if path:
        print("[full output: %s]" % path, file=sys.stderr)
    return path


def print_lossless_stdout(cmd, result, config):
    """stdout in the run_lossless form (a cap cut forces a tee and names
    its path), then the masked stderr; without a cut, tee per tee.mode.

    Summary paths use it where their compactor would print nothing: a
    non-zero exit (stdout survives, TK-61) or an empty compactor result.
    Returns the stdout text printed.
    """
    raw = result.stdout or ""
    try:
        texts, cut, path = _lossless_streams(
            cmd, result, config, [(raw, redaction.redact_text(raw))]
        )
        stdout = texts[0]
        stderr = redaction.redact_text(result.stderr or "")
    except Exception:
        raw_fallback(result)
        return raw
    if stdout:
        print(stdout, end="")
        if not stdout.endswith("\n"):
            print()
    if stderr:
        print(stderr, end="", file=sys.stderr)
    _finish_tee(cmd, result, config, cut, path)
    return stdout


def compacted_result(cmd, result, config, compact_fn, tee_policy="auto",
                     strategy="compact", never_empty=True):
    """Compact stdout for any exit code; fall back to raw output on error.

    Never empty (TK-61): when the compactor yields only whitespace while raw
    stdout is not empty, the run_lossless form of stdout is printed instead.
    never_empty=False is the user-chosen `actx run --failures` mode, where
    an empty result is the answer (green run -> silent).
    """
    if result is None:
        return 1
    try:
        out = compact_fn(result)
        if out is None:
            return raw_fallback(result)
        cut, path = False, None
        if never_empty and not out.strip() and (result.stdout or "").strip():
            raw = result.stdout
            texts, cut, path = _lossless_streams(
                cmd, result, config, [(raw, redaction.redact_text(raw))]
            )
            out = texts[0]
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
        tracking.record(
            cmd, cmd[0], raw_bytes, emitted, result.returncode, strategy=strategy,
            store_text=not _secret_bearing_result(result),
        )
        _finish_tee(cmd, result, config, cut, path, tee_policy)
        try:
            for hint in _session_hints(result):
                print(hint, file=sys.stderr)
        except Exception:
            pass
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
    tracking.record(
        cmd, cmd[0], raw_bytes, emitted, result.returncode, strategy="errors",
        store_text=not _secret_bearing_result(result),
    )
    try:
        for hint in _session_hints(result):
            print(hint, file=sys.stderr)
    except Exception:
        pass
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
    tracking.record(
        cmd, cmd[0], raw_bytes, emitted, result.returncode, strategy="digest",
        store_text=not _secret_bearing_result(result),
    )
    try:
        for hint in _session_hints(result):
            print(hint, file=sys.stderr)
    except Exception:
        pass
    return result.returncode
