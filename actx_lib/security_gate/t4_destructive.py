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
    "sh", "bash", "zsh", "dash", "ksh", "perl", "ruby", "node", "php",
})


def _is_find_exec_interpreter(head: str) -> bool:
    return head in _FIND_EXEC_INTERPRETERS or head.startswith("python")


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
                _is_find_exec_interpreter(args[0]) and len(args) >= 2 and args[1] == "{}"
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
