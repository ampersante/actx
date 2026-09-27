"""actx security gate - T4: destructive OS mutations & persistence hijacking,
including find -exec/-execdir/-ok/-okdir subcommand recursion (TK-59 split).

Body unchanged from the pre-split monolith - see tools/ast_identity_check.py.
"""

import os
import posixpath
import re
import shlex

from .common import SecurityDecision, _strip_redirection, _unwrap_tokens, _RE_FORK_BOMB


_PERSISTENCE_FILES = {
    ".zshrc",
    ".zshenv",
    ".zprofile",
    ".zlogin",
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".profile",
    "config.fish",
}


# ----------------------------------------------------------------------
# T4: Destructive OS Mutations & Persistence Hijacking
# ----------------------------------------------------------------------

_DANGEROUS_TARGET_PREFIXES = (
    "/",
    "/*",
    "~",
    "~/",
    "$HOME",
    "$HOME/",
    "${HOME}",
    "${HOME}/",
    "/root",
    "/root/",
    "/etc",
    "/etc/",
    "/usr",
    "/usr/",
    "/bin",
    "/sbin",
    "/var",
    "/opt",
    "/System",
    "/Library",
    "/private",
    "/boot",
    "/dev",
    "/sys",
    "/proc",
    ".*",
)

_PROTECTED_USER_DIRS = {
    "Downloads",
    "Documents",
    "Applications",
    "Desktop",
    "Pictures",
    "Music",
    "Movies",
}


def _is_critical_system_target(norm_t: str, raw_target: str) -> bool:
    for p in _DANGEROUS_TARGET_PREFIXES:
        if norm_t == p or norm_t.startswith(p + "/") or norm_t.startswith(p + "*"):
            return True

    # Check root user paths /Users, /home, /Users/username, /home/username, ~/
    if raw_target.startswith("/") or raw_target.startswith("~") or raw_target.startswith("$"):
        parts = [p for p in norm_t.strip("/").split("/") if p]
        if parts and parts[0] in ("Users", "home"):
            # /Users or /Users/username
            if len(parts) <= 2:
                return True
            # /Users/username/Desktop, /Users/username/Downloads, /Users/username/Documents, etc.
            if len(parts) == 3 and parts[2] in _PROTECTED_USER_DIRS:
                return True
            if len(parts) == 4 and parts[2] in _PROTECTED_USER_DIRS and parts[3] in ("*", ".*"):
                return True
        elif parts and (parts[0] == "~" or norm_t.startswith("~")):
            # ~, ~/Desktop, ~/Downloads, etc.
            if len(parts) <= 1:
                return True
            if len(parts) == 2 and parts[1] in _PROTECTED_USER_DIRS:
                return True
            if len(parts) == 3 and parts[1] in _PROTECTED_USER_DIRS and parts[2] in ("*", ".*"):
                return True
    return False


def _check_destructive_and_persistence(command: str, raw_tokens: list[str]) -> SecurityDecision | None:
    # Fork bomb
    if ":" in command and "{" in command and _RE_FORK_BOMB.search(command):
        return SecurityDecision(
            decision="deny",
            reason="Fork bomb execution pattern detected",
            category="T4_DESTRUCTIVE_MUTATION",
        )

    tokens = _unwrap_tokens(raw_tokens)
    if not tokens:
        return None

    head = os.path.basename(tokens[0])

    # Root / home destruction: rm -rf / or rm --recursive --force / or rm -rf ~
    if head == "rm":
        rm_args = tokens[1:]
        has_r = False
        has_f = False
        targets = []
        for arg in rm_args:
            clean_arg = _strip_redirection(arg)
            if clean_arg in ("-rf", "-fr", "-r", "-R", "--recursive", "-f", "--force") or (
                clean_arg.startswith("-") and not clean_arg.startswith("--") and any(c in clean_arg.lower() for c in ("r", "f", "d"))
            ):
                if "r" in clean_arg.lower() or "--recursive" in clean_arg or "d" in clean_arg:
                    has_r = True
                if "f" in clean_arg.lower() or "--force" in clean_arg:
                    has_f = True
            elif not clean_arg.startswith("-"):
                targets.append(clean_arg)

        if has_r or has_f:
            for t in targets:
                norm_t = re.sub(r"/+", "/", t)
                try:
                    norm_t = posixpath.normpath(norm_t)
                except Exception:
                    pass
                if _is_critical_system_target(norm_t, t):
                    return SecurityDecision(
                        decision="deny",
                        reason=f"Destructive recursive deletion of critical target '{norm_t}' is prohibited",
                        category="T4_DESTRUCTIVE_MUTATION",
                    )

    # find / -delete or find / -exec rm
    if head == "find":
        if any(tok in ("-delete", "-exec", "-execdir", "-ok", "-okdir") for tok in tokens[1:]):
            for tok in tokens[1:]:
                norm_t = re.sub(r"/+", "/", tok)
                try:
                    norm_t = posixpath.normpath(norm_t)
                except Exception:
                    pass
                if _is_critical_system_target(norm_t, tok):
                    return SecurityDecision(
                        decision="deny",
                        reason=f"Destructive find deletion of critical directory '{norm_t}' is prohibited",
                        category="T4_DESTRUCTIVE_MUTATION",
                    )

    # crontab modification
    if head == "crontab":
        if len(tokens) >= 2 and any(t not in ("-l",) for t in tokens[1:]):
            return SecurityDecision(
                decision="deny",
                reason="Tampering with crontab is prohibited",
                category="T4_DESTRUCTIVE_MUTATION",
            )

    # Dangerous recursive permission or ownership alteration
    if head in ("chmod", "chown", "chgrp"):
        has_R = any(tok in ("-R", "--recursive") or (tok.startswith("-") and not tok.startswith("--") and "R" in tok) for tok in tokens[1:])
        if has_R:
            for tok in tokens[1:]:
                norm_t = re.sub(r"/+", "/", tok)
                try:
                    norm_t = posixpath.normpath(norm_t)
                except Exception:
                    pass
                if _is_critical_system_target(norm_t, tok):
                    return SecurityDecision(
                        decision="deny",
                        reason=f"Recursive permission/ownership alteration on critical directory '{norm_t}' is prohibited",
                        category="T4_DESTRUCTIVE_MUTATION",
                    )

    # Disk formatting / raw writing: mkfs, mke2fs, mkswap, parted, sfdisk, diskutil, dd
    if (
        head.startswith("mkfs")
        or head.startswith("mke2fs")
        or head in ("mkswap", "fdisk", "gdisk", "parted", "sfdisk", "wipefs", "shred", "diskutil", "newfs_apfs")
    ):
        return SecurityDecision(
            decision="deny",
            reason=f"Disk formatting or partition alteration via '{head}' is prohibited",
            category="T4_DESTRUCTIVE_MUTATION",
        )

    if head == "dd":
        for tok in tokens[1:]:
            if tok.startswith("of=/dev/") or tok.startswith("of=/etc/"):
                return SecurityDecision(
                    decision="deny",
                    reason="Raw disk or system partition writing via dd is prohibited",
                    category="T4_DESTRUCTIVE_MUTATION",
                )

    # Privilege escalation: sudo, su, doas, pkexec, sudoedit
    if head in ("sudo", "su", "doas", "pkexec", "sudoedit", "nsenter"):
        return SecurityDecision(
            decision="deny",
            reason=f"Privilege escalation via '{head}' is prohibited in autonomous agent sessions",
            category="T4_DESTRUCTIVE_MUTATION",
        )

    # Persistence tampering: writing to shell profile, cron dirs, launch agents, or git hooks
    if any(op in command for op in (">", "tee", "cp", "mv", "install", "ln", "sed", "dd", "rm")):
        for tok in tokens:
            clean = _strip_redirection(tok).strip("'\"")
            base = os.path.basename(clean.replace("\\", "/"))
            if base in _PERSISTENCE_FILES or clean in ("/etc/crontab", "/etc/profile") or clean.startswith("/etc/cron"):
                return SecurityDecision(
                    decision="deny",
                    reason=f"Tampering with shell startup/persistence file '{base}' is prohibited",
                    category="T4_DESTRUCTIVE_MUTATION",
                )
            if ".git/hooks" in clean.replace("\\", "/"):
                return SecurityDecision(
                    decision="deny",
                    reason="Tampering with git hooks directory is prohibited",
                    category="T4_DESTRUCTIVE_MUTATION",
                )

    return None


# ----------------------------------------------------------------------
# T4 (recursive): find -exec/-execdir/-ok/-okdir subcommand re-evaluation
# (TK-57 S6, REQ-06)
# ----------------------------------------------------------------------

_FIND_EXEC_FLAGS = ("-exec", "-execdir", "-ok", "-okdir")
_FIND_EXEC_INTERPRETERS = frozenset({
    "sh", "bash", "zsh", "dash", "ksh", "perl", "ruby", "node", "nodejs", "php",
})


def _is_find_exec_interpreter(head: str) -> bool:
    return head in _FIND_EXEC_INTERPRETERS or head.startswith("python")


# TK-60 STEP-G2 (REQ-09): interpreter -> its own VALUE-taking options (the
# option consumes the NEXT argv token as a value). Sources (local --help/man,
# 2026-09-27, except node/php - not installed here, well-known documented
# CLI flags): sh/bash/zsh/dash/ksh -c (inline script) / -o (named option,
# e.g. -o pipefail); bash --rcfile/--init-file (man bash OPTIONS: each takes
# `file` as a SEPARATE following token - finding C, wave 2026-09-27); node
# -e/--eval (inline script) / -r/--require (preload module); perl -e/-E
# (inline script, `perl -h`); ruby -e (inline script, `ruby --help`); php -r
# (inline code, official docs).
_INTERPRETER_VALUE_FLAGS = {
    "sh": frozenset({"-c", "-o"}),
    "bash": frozenset({"-c", "-o", "--rcfile", "--init-file"}),
    "zsh": frozenset({"-c", "-o"}),
    "dash": frozenset({"-c", "-o"}),
    "ksh": frozenset({"-c", "-o"}),
    "node": frozenset({"-e", "--eval", "-r", "--require"}),
    "nodejs": frozenset({"-e", "--eval", "-r", "--require"}),
    "perl": frozenset({"-e", "-E"}),
    "ruby": frozenset({"-e"}),
    "php": frozenset({"-r"}),
}
# python*: -c (inline script), -m (run module), -W (warning filter value),
# -X (implementation option value), --check-hash-based-pycs (value is the
# next token: always|default|never - finding C, `python3 --help` 2026-09-27).
_PYTHON_VALUE_FLAGS = frozenset({"-c", "-m", "-W", "-X", "--check-hash-based-pycs"})

# Finding C (wave 2026-09-27, gate REJECT): interpreter options that are
# confirmed to take NO value at all (same sources as above, plus the `set`
# builtin's single-char options - man bash: "set [--abefhkmnptuvxBCHP]" -
# which bash (and, per POSIX.1 sh, dash/zsh/ksh too) also accepts directly
# at invocation, e.g. `bash -e -x script.sh`). Any option NOT in this set
# and NOT in the value-flags table is now UNKNOWN and fails closed to "ask"
# instead of being assumed boolean - the previous default ("anything
# starting with '-' that isn't a known value flag is boolean") let an
# unrecognized VALUE-taking option (bash --rcfile, python3
# --check-hash-based-pycs) swallow its value into what the scanner then
# treated as the script position, so the real `{}` later in argv was never
# inspected and the command was silently allowed. Booleans are enumerated
# only to avoid unnecessary loss of the known-script idiom's compression
# (`bash -e -x known.sh {}`); an interpreter/flag pair missing from BOTH
# tables safely falls through to ask - no security dependency on this list
# being exhaustive.
_POSIX_SET_BOOL_FLAGS = frozenset({"-a", "-b", "-C", "-e", "-f", "-h", "-m", "-n", "-u", "-v", "-x"})
_INTERPRETER_BOOL_FLAGS = {
    "sh": _POSIX_SET_BOOL_FLAGS | {"-i", "-s"},
    "bash": _POSIX_SET_BOOL_FLAGS | {
        "-i", "-l", "-r", "-s", "-t", "-k", "-p", "-B", "-E", "-H", "-P", "-T", "-D",
        "--debugger", "--dump-po-strings", "--dump-strings", "--help",
        "--login", "--noediting", "--noprofile", "--norc", "--posix",
        "--restricted", "--verbose", "--version",
    },
    "zsh": _POSIX_SET_BOOL_FLAGS | {"-i", "-s"},
    "dash": _POSIX_SET_BOOL_FLAGS | {"-i", "-s"},
    "ksh": _POSIX_SET_BOOL_FLAGS | {"-i", "-s"},
    "perl": frozenset({
        "-a", "-c", "-f", "-n", "-p", "-s", "-S", "-t", "-T", "-u", "-U",
        "-v", "-w", "-W", "-X",
    }),
    "ruby": frozenset({
        "-a", "-c", "-d", "--debug", "-l", "-n", "-p", "-s", "-S", "-v",
        "-w", "--verbose", "--version", "--help", "--copyright",
    }),
}
_PYTHON_BOOL_FLAGS = frozenset({
    "-b", "-B", "-d", "-E", "-h", "-i", "-I", "-O", "-OO", "-P", "-q", "-s",
    "-S", "-t", "-u", "-v", "-V", "-x", "--help", "--help-env",
    "--help-xoptions", "--help-all",
})


def _interpreter_value_flags(head: str) -> frozenset:
    if head.startswith("python"):
        return _PYTHON_VALUE_FLAGS
    return _INTERPRETER_VALUE_FLAGS.get(head, frozenset())


def _interpreter_bool_flags(head: str) -> frozenset:
    if head.startswith("python"):
        return _PYTHON_BOOL_FLAGS
    return _INTERPRETER_BOOL_FLAGS.get(head, frozenset())


def _find_exec_script_arg_is_placeholder(interpreter: str, args: list[str]) -> bool:
    """True when `{}` reaches the interpreter's OWN argv as its script or
    as a value-flag's value (REQ-09 G2) - direct execution of an unknown
    discovered file (`sh {}`, `python3 -u {}`), or `{}` fed straight into
    an inline-code invocation (`sh -c 'echo ok' {}`, `node -r {}`).

    Walks past the interpreter's own value-flags (table above, value
    consumed with them) and unrecognized boolean-shaped flags; the first
    non-flag token reached is the "script position". A script FILE given
    there (anything other than `{}`) is the standard, safe find-exec idiom
    (`-exec python3 lint.py {} \\;`) - later positionals are the KNOWN
    script's own arguments and are deliberately not inspected further.
    """
    value_flags = _interpreter_value_flags(interpreter)
    bool_flags = _interpreter_bool_flags(interpreter)
    i = 0
    n = len(args)
    while i < n:
        tok = args[i]
        if tok == "--":
            # Standard end-of-options marker for every supported interpreter:
            # the next token is the script position.
            return i + 1 < n and args[i + 1] == "{}"
        if tok in value_flags:
            if i + 1 >= n:
                return False
            if args[i + 1] == "{}":
                return True
            i += 2
            continue
        if tok in bool_flags:
            i += 1
            continue
        if tok.startswith("-"):
            # Unrecognized option (finding C): fail closed rather than
            # assume it takes no value - we cannot prove it won't swallow
            # the next token, so `{}` is treated as reachable here.
            return True
        return tok == "{}"
    return False


def _check_find_exec_subcommands(raw_tokens: list[str]) -> SecurityDecision | None:
    """Re-evaluate every find -exec/-execdir/-ok/-okdir subcommand as its
    own command, per find's own terminator grammar: ';' always ends a
    clause; '+' ends one only when it directly follows '{}' (elsewhere '+'
    is an ordinary argument, e.g. `git -C + reset --hard`); an unterminated
    clause runs to the end of the token list (fail-open, no exception).
    '{}' standing in head position (`-exec {} \\;`) or as the first
    argument to a known interpreter (`-exec sh {} \\;`) means find would
    execute an unknown discovered file directly - ask (T4) regardless of
    what the recursive re-evaluation of the rest of the clause finds.
    Multiple clauses: deny on the first one that denies; otherwise ask if
    any clause asks (REQ-06's "same or a stricter verdict").
    """
    tokens = _unwrap_tokens(raw_tokens)
    if not tokens or os.path.basename(tokens[0]) != "find":
        return None

    ask_decision: SecurityDecision | None = None
    i = 1
    n = len(tokens)
    while i < n:
        if tokens[i] not in _FIND_EXEC_FLAGS:
            i += 1
            continue
        j = i + 1
        args: list[str] = []
        terminated = False
        while j < n:
            t = tokens[j]
            if t == ";":
                j += 1
                terminated = True
                break
            if t == "+":
                if args and args[-1] == "{}":
                    j += 1
                    terminated = True
                    break
                args.append(t)
                j += 1
                continue
            args.append(t)
            j += 1

        if args:
            if args[0] == "{}" or (
                _is_find_exec_interpreter(args[0])
                and _find_exec_script_arg_is_placeholder(args[0], args[1:])
            ):
                ask_decision = ask_decision or SecurityDecision(
                    decision="ask",
                    reason="find executes an unknown discovered file directly ('{}' as the executed program)",
                    category="T4_DESTRUCTIVE_MUTATION",
                )

            sub_tokens = ["actx_find_arg" if t == "{}" else t for t in args]
            # Back-edge (TK-59 STEP-R2): local import avoids a t4_destructive
            # <-> engine module cycle (engine imports _check_find_exec_
            # subcommands at module load time).
            from .engine import _evaluate_chunk
            sub_dec = _evaluate_chunk(shlex.join(sub_tokens))
            if sub_dec.decision == "deny":
                return sub_dec
            if sub_dec.decision == "ask":
                ask_decision = ask_decision or sub_dec

        i = j if terminated else n

    return ask_decision
