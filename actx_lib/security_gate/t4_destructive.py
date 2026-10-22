"""actx security gate - T4: destructive OS mutations & persistence hijacking,
including find -exec/-execdir/-ok/-okdir subcommand recursion (TK-59 split)
and the TK-63 literal-target zone classifier for rm / chmod-chown-chgrp -R /
find.
"""

import fnmatch
import functools
import os
import posixpath
import re
import shlex

from .common import (
    SecurityDecision, _strip_redirection, _unwrap_tokens, _RE_FORK_BOMB,
    _WRAPPER_COMMANDS,
)
from .t1_paths import _protected_home_entries


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


def _today_normalised(token: str) -> str:
    norm_t = re.sub(r"/+", "/", token)
    try:
        norm_t = posixpath.normpath(norm_t)
    except Exception:
        pass
    return norm_t


# ----------------------------------------------------------------------
# TK-63: literal-target grammar and zone classifier
# ----------------------------------------------------------------------
# An exemption from today's prefix verdict exists only for a target word of
# a single command inside the engine's closed grammar
# (engine._closed_grammar_words) that the target grammar below fully
# describes: an anchor (`~`, `$HOME/`, `${HOME}/`, or `/`), then components
# from a literal charset, with an exact `*` allowed only as the final
# component. Anything else - and every target of a command outside the
# engine grammar - keeps today's verdict (_is_critical_system_target).
# Classification is lexical and case-insensitive (APFS default); symlinks
# are not resolved.
_RE_LITERAL_COMPONENT = re.compile(r"[A-Za-z0-9._ +@%,=:-]+")

# Protected stores (home-relative; owner-confirmed list B, TK-63):
# C = credentials, D = data. Deny at any depth, ancestors included. The T1
# home records (t1_paths._PROTECTED_PATHS) join as class C at use.
_PROTECTED_STORES = (
    ("C", ".ssh"), ("C", ".gnupg"), ("C", ".aws"), ("C", ".azure"),
    ("C", ".kube"), ("C", ".docker"), ("C", ".config"),
    ("C", ".password-store"), ("C", ".local/share/keyrings"),
    ("C", ".netrc"), ("C", "Library/Keychains"), ("C", "Library/Cookies"),
    ("D", ".claude"), ("D", ".codex"), ("D", "Library/Mobile Documents"),
    ("D", "Library/Mail"), ("D", "Library/Messages"),
    ("D", "Library/Application Support"), ("D", "Library/Containers"),
    ("D", "Library/Group Containers"), ("D", "Library/Preferences"),
    ("D", "Library/Safari"),
)
_SYSTEM_ROOTS = frozenset(r.casefold() for r in (
    "etc", "usr", "bin", "sbin", "var", "opt", "System", "Library",
    "private", "boot", "dev", "sys", "proc", "root",
))
_HOME_PARENTS = ("users", "home")


def _components(path: str) -> list[str]:
    return [c for c in path.split("/") if c not in ("", ".")]


def _is_glob(pattern: str) -> bool:
    return any(ch in pattern for ch in "*?[")


@functools.lru_cache(maxsize=16)
def _store_patterns(home: str) -> tuple:
    """Home-relative protected stores of list B plus the T1 home records
    (one source: _protected_home_entries), casefolded, as
    (by_first, globbed_first, all_classes): stores indexed by their literal
    first component, stores whose first component is a glob, and the set
    of every store class (an ancestor of the home reaches all of them)."""
    stores = [(cls, tuple(c.casefold() for c in _components(rel))) for cls, rel in _PROTECTED_STORES]
    for _abs_p, rel_p, _deep in _protected_home_entries(home):
        if not rel_p.startswith("/"):
            stores.append(("C", tuple(c.casefold() for c in _components(rel_p))))
    by_first: dict[str, list] = {}
    globbed = []
    for cls, store in stores:
        if not store:
            continue
        if _is_glob(store[0]):
            globbed.append((cls, store))
        else:
            by_first.setdefault(store[0], []).append((cls, store))
    return by_first, tuple(globbed), frozenset(cls for cls, _store in stores)


def _component_match(comp: str, pattern: str) -> bool:
    if _is_glob(pattern):
        return fnmatch.fnmatchcase(comp, pattern)
    return comp == pattern


def _intersects(path: list[str], store: tuple) -> bool:
    """path equals, is inside, or is an ancestor of store."""
    return all(_component_match(p, q) for p, q in zip(path, store))


def _store_classes(path: list[str], home: list[str], stores: tuple) -> set:
    """Classes of the stores below `home` that `path` equals, is inside, or
    is an ancestor of."""
    if len(path) <= len(home):
        return set(stores[2]) if path == home[:len(path)] else set()
    if path[:len(home)] != home:
        return set()
    rel = path[len(home):]
    by_first, globbed, _all = stores
    return {
        cls
        for cls, store in (*by_first.get(rel[0], ()), *globbed)
        if _intersects(rel, store)
    }


def _temp_root_len(path: list[str]) -> int:
    """Component count of the temp root `path` starts with, or 0: /tmp,
    /var/tmp, /var/folders/<a>/<b>/T, each also under /private."""
    off = 1 if path[:1] == ["private"] else 0
    rest = path[off:]
    if rest[:1] == ["tmp"]:
        return off + 1
    if rest[:2] == ["var", "tmp"]:
        return off + 2
    if len(rest) >= 5 and rest[:2] == ["var", "folders"] and rest[4] == "t":
        return off + 5
    return 0


def _path_zones(path: list[str], home: list[str] | None, home_str: str) -> set:
    """Deny zones of an absolute, casefolded component list (§2.1 table).
    A protected user dir is a direct child of a home, so the home row
    already covers it. A temp root itself is the temp zone only - not
    shallow, not system: it denies for rm, and for find it is class K
    (§2.3)."""
    zones = set()
    temp = _temp_root_len(path)
    if temp and len(path) == temp:
        zones.add("temp")
    elif len(path) <= 1:
        zones.add("shallow")
    homes = [home] if home is not None else []
    if len(path) >= 2 and path[0] in _HOME_PARENTS and path[:2] != home:
        homes.append(path[:2])
    stores = _store_patterns(home_str)
    for h in homes:
        if path[:len(h)] == h and len(path) - len(h) <= 1:
            zones.add("home")
        zones |= _store_classes(path, h, stores)
    if path and path[0] in _SYSTEM_ROOTS and not temp:
        zones.add("system")
    return zones


def classify_target(token: str, glob: bool = False) -> set | None:
    """Deny zones of a literal target word (§2.1) of a command inside the
    engine's closed grammar, or None when the word is no literal target
    (the caller then applies today's verdict). An empty
    set means no deny zone; "dotdot" marks a `..` component (always deny).
    A final `*` stands for the children of its parent and gets the parent's
    zones: every deny zone a child can be in is a zone the parent already
    carries (home child, store ancestor, temp root, system root). `glob`:
    the engine grammar saw that final `*` UNQUOTED; a quoted `*` is a
    literal name, no literal component, so the word gets today's verdict."""
    home_anchor = True
    # In the closed grammar `~` is unquoted and `$HOME/` / `${HOME}/` open a
    # double-quoted word - the two forms the shell expands to the home.
    if token == "~" or token.startswith("~/"):
        rest = token[1:]
    elif token.startswith("$HOME/"):
        rest = token[5:]
    elif token.startswith("${HOME}/"):
        rest = token[7:]
    elif token.startswith("/"):
        rest, home_anchor = token, False
    else:
        return None
    comps = _components(rest)
    if glob and comps and comps[-1] == "*":
        comps = comps[:-1]
    if not all(_RE_LITERAL_COMPONENT.fullmatch(c) for c in comps):
        return None
    if ".." in comps:
        return {"dotdot"}
    home_str = os.path.expanduser("~")
    if not home_str.startswith("/"):
        if home_anchor:
            return None
        return _path_zones([c.casefold() for c in comps], None, home_str)
    home = [c.casefold() for c in _components(home_str)]
    path = (home if home_anchor else []) + [c.casefold() for c in comps]
    return _path_zones(path, home, home_str)


def _denied_target(targets: list[str], words: list[tuple[str, bool]] | None) -> tuple[str, bool] | None:
    """(token named in the reason, by_dotdot) when one rm / chmod-chown-
    chgrp target is denied, or None. `targets` are today's tokens; `words`
    the (shell word, unquoted-glob) targets of a command inside the closed
    grammar, or None
    (today's verdict). A word gets the zone verdict, a word that is no
    literal target today's check. The reason names today's first critical
    target whenever today's code denies too, so an unchanged verdict keeps
    today's text; by_dotdot marks a deny the `..` rule alone produced."""
    if words is None:
        for tok in targets:
            if _is_critical_system_target(_today_normalised(tok), tok):
                return tok, False
        return None
    new_hit = None
    for tok, glob in words:
        zones = classify_target(tok, glob)
        if zones is None:
            zones = {"today"} if _is_critical_system_target(_today_normalised(tok), tok) else set()
        if zones:
            new_hit = (tok, zones)
            break
    if new_hit is None:
        return None
    for tok in targets:
        if _is_critical_system_target(_today_normalised(tok), tok):
            return tok, False
    return new_hit[0], "dotdot" in new_hit[1]


# find (§2.3): the closed expression grammar, BSD find(1) and GNU findutils.
_FIND_OPERATORS = frozenset({"!", "-not", "(", ")", "-a", "-and", "-o", "-or", ","})
_FIND_LEADING_OPTIONS = frozenset({"-H", "-L", "-P", "-E", "-X", "-s", "-x", "-d"})
_FIND_ARITY0 = _FIND_LEADING_OPTIONS | frozenset({
    "-depth", "-empty", "-sparse", "-nouser", "-nogroup", "-mount", "-xdev",
    "-follow", "-noleaf", "-daystart", "-ignore_readdir_race",
    "-noignore_readdir_race", "-readable", "-writable", "-executable",
    "-nowarn", "-warn", "-acl", "-xattr", "-true", "-false", "-prune",
    "-quit", "-print", "-print0", "-ls",
})
# The next token is consumed whatever it looks like (`-mtime -7`).
_FIND_ARITY1 = frozenset({
    "-name", "-iname", "-path", "-ipath", "-wholename", "-iwholename",
    "-regex", "-iregex", "-lname", "-ilname", "-type", "-xtype", "-size",
    "-mtime", "-mmin", "-atime", "-amin", "-ctime", "-cmin", "-Btime",
    "-Bmin", "-newer", "-anewer", "-cnewer", "-mnewer", "-Bnewer", "-perm",
    "-user", "-group", "-uid", "-gid", "-links", "-inum", "-samefile",
    "-flags", "-fstype", "-xattrname", "-maxdepth", "-mindepth",
    "-regextype", "-used", "-printf",
})
_RE_FIND_NEWERXY = re.compile(r"-newer[aBcmt][aBcmt]")
# Read-only exec programs: metadata printers (classes D, K, N) and content
# printers (classes K, N only). `file` is excluded: `file -C` writes.
_FIND_METADATA_PROGRAMS = frozenset({"stat", "ls"})
_FIND_CONTENT_PROGRAMS = frozenset({
    "cat", "head", "grep", "egrep", "fgrep", "wc", "md5", "md5sum",
    "shasum", "sha1sum", "sha256sum", "tail",
})
_RE_TAIL_COUNT = re.compile(r"\+?\d+")
_RE_TAIL_ATTACHED = re.compile(r"-[nc]\+?\d+|-\d+|\+\d+")
_FIND_CLASS_RANK = {"N": 0, "K": 1, "D": 2, "C": 3, "T": 3}


def _find_exec_clauses(tokens: list[str]) -> list[tuple[int, list[str]]] | None:
    """[(program index, clause argv)] when every token after the starting
    points is inside the closed find grammar; None otherwise."""
    i, n = 1, len(tokens)
    while i < n and tokens[i] in _FIND_LEADING_OPTIONS:
        i += 1
    while i < n and not tokens[i].startswith("-") and tokens[i] not in _FIND_OPERATORS:
        i += 1
    clauses = []
    while i < n:
        tok = tokens[i]
        if tok in _FIND_OPERATORS or tok in _FIND_ARITY0:
            i += 1
        elif tok in _FIND_ARITY1 or _RE_FIND_NEWERXY.fullmatch(tok):
            if i + 1 >= n:
                return None
            i += 2
        elif tok in ("-exec", "-execdir"):
            # Clause ends at the first `;`, or at a `+` right after `{}`.
            j = i + 1
            while j < n and tokens[j] != ";" and not (
                tokens[j] == "+" and j > i + 1 and tokens[j - 1] == "{}"
            ):
                j += 1
            if j >= n or j == i + 1:
                return None
            clauses.append((i + 1, tokens[i + 1:j]))
            i = j + 1
        else:
            return None
    return clauses


def _find_exec_program_indices(tokens: list[str]) -> set:
    """Program word indices of every -exec/-execdir/-ok/-okdir clause, by a
    syntactic scan that does not need the whole expression to be inside the
    find grammar: a known one-value primary skips its value, a clause ends
    at the first `;` or at a `+` right after `{}`. Where the grammar holds,
    these are exactly the _find_exec_clauses program indices."""
    out, i, n = set(), 1, len(tokens)
    while i < n:
        tok = tokens[i]
        if tok in _FIND_ARITY1 or _RE_FIND_NEWERXY.fullmatch(tok):
            i += 2
            continue
        if tok in ("-exec", "-execdir", "-ok", "-okdir"):
            if i + 1 < n:
                out.add(i + 1)
            j = i + 1
            while j < n and tokens[j] != ";" and not (
                tokens[j] == "+" and j > i + 1 and tokens[j - 1] == "{}"
            ):
                j += 1
            i = j + 1
            continue
        i += 1
    return out


def _find_program(token: str) -> str | None:
    """Program name of a bare or /bin, /usr/bin exec token; None for any
    other path (`./cat`, `/usr/local/bin/cat` are other programs)."""
    if "/" not in token:
        return token
    parent, _, name = token.rpartition("/")
    return name if parent in ("/bin", "/usr/bin") and name else None


def _tail_read_only(args: list[str]) -> bool:
    """Closed tail option set: -n N, -c N, -nN, -cN, -q, -v, -N, +N; every
    other token is `{}` or a literal operand."""
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ("-n", "-c"):
            if i + 1 >= len(args) or not _RE_TAIL_COUNT.fullmatch(args[i + 1]):
                return False
            i += 2
            continue
        if arg in ("-q", "-v") or _RE_TAIL_ATTACHED.fullmatch(arg):
            i += 1
            continue
        if arg.startswith("-"):
            return False
        i += 1
    return True


def _find_class(zones: set) -> str:
    if zones & {"dotdot", "shallow", "system"}:
        return "T"
    if "C" in zones:
        return "C"
    if "D" in zones:
        return "D"
    if zones & {"home", "temp"}:
        return "K"
    return "N"


def _find_deny(norm_t: str) -> SecurityDecision:
    return SecurityDecision(
        decision="deny",
        reason=f"Destructive find deletion of critical directory '{norm_t}' is prohibited",
        category="T4_DESTRUCTIVE_MUTATION",
    )


def _find_today(tokens: list[str]) -> SecurityDecision | None:
    for tok in tokens[1:]:
        norm_t = _today_normalised(tok)
        if _is_critical_system_target(norm_t, tok):
            return _find_deny(norm_t)
    return None


def _check_find_targets(
    tokens: list[str], words: list[str] | None, globs: tuple[bool, ...] = ()
) -> SecurityDecision | None:
    """§2.3 over the shell words of a command inside the engine's closed
    grammar (`words`; None: today's verdict on today's tokens): the worst
    class over every word after `find` except the program word of every
    exec clause (a program is admitted or not by _find_read_only, never
    classified as a target). T and C deny; D, K and N lose today's deny
    only for an expression inside the find grammar whose every exec program
    is read-only for that class; anything else gets today's verdict.
    `globs[i]`: words[i] ends in an unquoted `*` component."""
    if words is None:
        return _find_today(tokens)
    clauses = _find_exec_clauses(words)
    skip = _find_exec_program_indices(words)
    worst, worst_tok = "N", None
    for idx in range(1, len(words)):
        if idx in skip:
            continue
        tok = words[idx]
        zones = classify_target(tok, idx < len(globs) and globs[idx])
        if zones is None:
            cls = "T" if _is_critical_system_target(_today_normalised(tok), tok) else "N"
        else:
            cls = _find_class(zones)
        if _FIND_CLASS_RANK[cls] > _FIND_CLASS_RANK[worst]:
            worst, worst_tok = cls, tok
    if worst in ("T", "C"):
        return _find_today(tokens) or _find_deny(_today_normalised(worst_tok))
    allowed = _FIND_METADATA_PROGRAMS
    if worst != "D":
        allowed = allowed | _FIND_CONTENT_PROGRAMS
    if clauses and all(_find_read_only(args, allowed) for _idx, args in clauses):
        return None
    return _find_today(tokens)


def _operand_indices(words: list[str]) -> list[int]:
    """rm operands: indices of the words after `rm` that are no option,
    every word after `--`."""
    out, end_of_options = [], False
    for i in range(1, len(words)):
        word = words[i]
        if end_of_options or not word.startswith("-"):
            out.append(i)
        elif word == "--":
            end_of_options = True
    return out


def _find_read_only(args: list[str], allowed: frozenset) -> bool:
    name = _find_program(args[0])
    return name in allowed and (name != "tail" or _tail_read_only(args[1:]))


def _check_destructive_and_persistence(
    command: str,
    raw_tokens: list[str],
    words: list[str] | None = None,
    globs: tuple[bool, ...] | None = None,
) -> SecurityDecision | None:
    # words (TK-63): the shell words of the whole command when it is a
    # single simple command inside the engine's closed grammar, else None;
    # only then do rm/find/chmod/chown/chgrp targets get the zone verdict.
    # globs[i]: words[i] ends in an unquoted `*` component.
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
    if words is not None and words[0] != head:
        words = None
    if words is not None:
        globs = tuple(globs) if globs is not None else (False,) * len(words)

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
            hit = _denied_target(
                targets,
                None if words is None else [(words[i], globs[i]) for i in _operand_indices(words)],
            )
            if hit and hit[1]:
                return SecurityDecision(
                    decision="deny",
                    reason=f"Destructive recursive deletion of a target with a '..' component '{hit[0]}' is prohibited",
                    category="T4_DESTRUCTIVE_MUTATION",
                )
            if hit:
                return SecurityDecision(
                    decision="deny",
                    reason=f"Destructive recursive deletion of critical target '{_today_normalised(hit[0])}' is prohibited",
                    category="T4_DESTRUCTIVE_MUTATION",
                )

    # find / -delete or find / -exec rm
    if head == "find":
        if any(tok in ("-delete", "-exec", "-execdir", "-ok", "-okdir") for tok in tokens[1:]):
            find_dec = _check_find_targets(tokens, words, globs or ())
            if find_dec:
                return find_dec

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
            hit = _denied_target(
                tokens[1:], None if words is None else list(zip(words[1:], globs[1:]))
            )
            if hit and hit[1]:
                return SecurityDecision(
                    decision="deny",
                    reason=f"Recursive permission/ownership alteration on a target with a '..' component '{hit[0]}' is prohibited",
                    category="T4_DESTRUCTIVE_MUTATION",
                )
            if hit:
                return SecurityDecision(
                    decision="deny",
                    reason=f"Recursive permission/ownership alteration on critical directory '{_today_normalised(hit[0])}' is prohibited",
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
    # node --help: common no-value options (value-taking long options are
    # normally spelled --opt=value, which the scan treats as self-contained).
    "node": frozenset({
        "-c", "--check", "-i", "--interactive", "--no-warnings",
        "--no-deprecation", "--throw-deprecation", "--trace-deprecation",
        "--trace-warnings", "--pending-deprecation", "--enable-source-maps",
        "--preserve-symlinks", "--preserve-symlinks-main", "--experimental-vm-modules",
    }),
}
_INTERPRETER_BOOL_FLAGS["nodejs"] = _INTERPRETER_BOOL_FLAGS["node"]
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


def _has_placeholder(tok: str) -> bool:
    # find substitutes `{}` anywhere inside an argument (`./{}`, `{}/x.js`,
    # `--require=./{}`), not only as a whole token.
    return "{}" in tok


def _executes_placeholder(args: list[str]) -> bool:
    """True when the -exec clause runs the discovered file as a program or
    interpreter script - directly, or through wrapper chains (`env {}`,
    `nice -n 5 {}`, `timeout 1 sh {}`) resolved with the gate's own
    unwrapper before any placeholder substitution."""
    effective = args
    if os.path.basename(args[0]) in _WRAPPER_COMMANDS:
        effective = _unwrap_tokens(args)
        if not effective:
            return True
        head = effective[0]
        # A placeholder the unwrapper skipped as a wrapper option/value
        # (`env -u {} x`) is still reachable: fail closed.
        skipped = args[:args.index(head)] if head in args else args
        if any(_has_placeholder(t) for t in skipped):
            return True
    return _has_placeholder(effective[0]) or (
        _is_find_exec_interpreter(effective[0])
        and _find_exec_script_arg_is_placeholder(effective[0], effective[1:])
    )


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
            # End-of-options marker (every supported interpreter): the next
            # token is the script position.
            return i + 1 < n and _has_placeholder(args[i + 1])
        if tok in value_flags:
            if i + 1 >= n:
                return False
            if _has_placeholder(args[i + 1]):
                return True
            i += 2
            continue
        if tok in bool_flags:
            i += 1
            continue
        if tok.startswith("--") and "=" in tok:
            # --opt=value carries its value inline; nothing else consumed.
            if _has_placeholder(tok):
                return True
            i += 1
            continue
        if (tok.startswith("-") and not tok.startswith("--") and len(tok) > 2
                and all("-" + c in bool_flags for c in tok[1:-1])):
            # Short-option cluster (`-ex`, `-bb`): every char but the last
            # is a documented boolean; the last is a boolean too, or a
            # value option that takes the next token (`-xc CODE`).
            last = "-" + tok[-1]
            if last in bool_flags:
                i += 1
                continue
            if last in value_flags:
                if i + 1 >= n:
                    return False
                if _has_placeholder(args[i + 1]):
                    return True
                i += 2
                continue
        if tok.startswith("-"):
            # Unrecognized option (finding C): fail closed rather than
            # assume it takes no value - we cannot prove it won't swallow
            # the next token, so `{}` is treated as reachable here.
            return True
        return _has_placeholder(tok)
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
            if _executes_placeholder(args):
                ask_decision = ask_decision or SecurityDecision(
                    decision="ask",
                    reason="find executes an unknown discovered file directly ('{}' as the executed program)",
                    category="T4_DESTRUCTIVE_MUTATION",
                )

            sub_tokens = [t.replace("{}", "actx_find_arg") for t in args]
            # Back-edge (TK-59 STEP-R2): local import avoids a t4_destructive
            # <-> engine module cycle (engine imports _check_find_exec_
            # subcommands at module load time).
            from .engine import _evaluate_chunk
            # Nested evaluation never gets the TK-63 exemptions (no words).
            sub_dec = _evaluate_chunk(shlex.join(sub_tokens))
            if sub_dec.decision == "deny":
                return sub_dec
            if sub_dec.decision == "ask":
                ask_decision = ask_decision or sub_dec

        i = j if terminated else n

    return ask_decision
