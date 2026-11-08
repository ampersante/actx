"""actx security gate - T6: high-risk git mutations (ask confirmation)
(TK-59 split).

Body unchanged from the pre-split monolith - see tools/ast_identity_check.py.
"""

import fnmatch
import os
import re

from actx_lib import cli_families

from .common import SecurityDecision, _strip_redirection, _unwrap_tokens



# ----------------------------------------------------------------------
# T6: High-Risk Git Mutations (Ask Confirmation)
# ----------------------------------------------------------------------

# TK-57 S7 (STEP-06, REQ-07): git config keys that redirect git into
# running an external program (a pager/editor/credential-helper/diff-
# filter/alias/...), regardless of what value is set. Source: git-config(1)
# "Variables" section (pager.*, core.*, credential.*, diff.*, merge.*,
# filter.*, gpg.*, remote.*, http(s).proxy, include(If).path, ...).
_GIT_ASK_CONFIG_KEYS_EXACT = frozenset({
    "core.pager", "core.sshcommand", "core.editor", "core.fsmonitor",
    "core.hookspath", "core.gitproxy", "core.askpass",
    "core.alternaterefscommand", "sequence.editor",
    "interactive.difffilter", "diff.external", "credential.helper",
    "gpg.program", "uploadpack.packobjectshook", "web.browser",
    "imap.tunnel", "sendemail.sendmailcmd", "include.path",
    "http.proxy", "https.proxy",
})
_GIT_ASK_CONFIG_KEYS_GLOB = (
    "diff.*.textconv", "diff.*.command", "difftool.*.cmd",
    "mergetool.*.cmd", "merge.*.driver", "filter.*.clean",
    "filter.*.smudge", "filter.*.process", "credential.*.helper",
    "gpg.*.program", "pager.*", "alias.*", "protocol.*.allow",
    "remote.*.uploadpack", "remote.*.receivepack", "man.*.cmd",
    "browser.*.cmd", "includeif.*.path", "http.*.proxy",
)


def _is_git_ask_config_key(key: str) -> bool:
    key = key.lower()
    if key in _GIT_ASK_CONFIG_KEYS_EXACT:
        return True
    return any(fnmatch.fnmatch(key, pat) for pat in _GIT_ASK_CONFIG_KEYS_GLOB)


# `git config` classification (legacy positional form and the git>=2.46
# verb form) - only a confirmed value WRITE of an exec-class key asks;
# `--get`/`-l`/`list`/`get`/... reads never do, even of the same key
# (REQ-07: `git config --get core.pager` stays unaffected).
_GIT_CONFIG_READ_VERBS = frozenset({"get", "get-all", "get-regexp", "get-urlmatch", "list", "edit"})
_GIT_CONFIG_WRITE_VERBS = frozenset({"set", "add", "unset", "unset-all", "replace-all"})
_GIT_CONFIG_READ_FLAGS = frozenset({
    "--get", "--get-all", "--get-regexp", "--get-urlmatch", "-l", "--list",
    "--name-only", "-e", "--edit",
})
_GIT_CONFIG_WRITE_FLAGS = frozenset({"--add", "--replace-all"})
# TK-57 S7 / TK-60 STEP-G3 (REQ-09): every VALUE-taking option of `git
# config` (`/usr/bin/git config --help`, 2026-09-27) that can appear
# BEFORE the key/verb - each consumes exactly one following token as its
# value (space form) or the same token's own "=<value>" suffix (attached
# form). Both forms verified against git 2.50.1: --type/--comment/
# --default confirmed live (space and "="); --value/--url follow the same
# "--opt=<value>" synopsis convention parse-options.c honors for every
# long option (spot-checked live: both accepted the space form without a
# usage error). A value-flag missing here misaligns the positional scan
# below - its value token gets mistaken for the key (E-001: `git config
# --type path core.pager /tmp/x` read "path" as the key, not
# "core.pager", and never asked).
_GIT_CONFIG_VALUE_FLAGS = frozenset({
    "-f", "--file", "--blob", "--type", "--comment", "--value",
    "--default", "--url",
})
_GIT_CONFIG_BOOL_FLAGS = frozenset({
    "--global", "--local", "--system", "--worktree", "--includes",
    "--no-includes", "-z", "--null", "--show-origin", "--show-scope",
    "--no-value", "--fixed-value", "--all", "--append", "--regexp",
    "--no-type", "--bool", "--int", "--bool-or-int", "--path",
    "--expiry-date", "--show-names", "--no-show-names",
})


def _git_config_value_flag_attached(tok: str) -> bool:
    """True when `tok` is the attached `--flag=value` spelling of a
    _GIT_CONFIG_VALUE_FLAGS member (its value needs no extra token)."""
    if not tok.startswith("--") or "=" not in tok:
        return False
    return tok.split("=", 1)[0] in _GIT_CONFIG_VALUE_FLAGS


def _git_config_is_write(sub_args: list[str]):
    """Classify `git config <sub_args>` as a value write or not, and
    return the config key it targets (None if none can be determined).
    Fails toward "not a write" on unrecognized syntax - REQ-07 only needs
    to ask on a confirmed exec-class key write, never to block a read."""
    verb = None
    saw_read_flag = False
    saw_write_flag = False
    positionals: list[str] = []
    i = 0
    n = len(sub_args)
    if n and sub_args[0] in _GIT_CONFIG_READ_VERBS | _GIT_CONFIG_WRITE_VERBS | {"rename-section", "remove-section"}:
        verb = sub_args[0]
        i = 1
    while i < n:
        tok = sub_args[i]
        if tok in _GIT_CONFIG_READ_FLAGS:
            saw_read_flag = True
        elif tok in _GIT_CONFIG_WRITE_FLAGS:
            saw_write_flag = True
        elif tok in _GIT_CONFIG_BOOL_FLAGS:
            pass
        elif tok in _GIT_CONFIG_VALUE_FLAGS:
            i += 1  # also skip its value - consumed before the key (G3)
        elif _git_config_value_flag_attached(tok):
            pass
        elif not tok.startswith("-"):
            positionals.append(tok)
        i += 1

    key = positionals[0] if positionals else None
    if verb in _GIT_CONFIG_READ_VERBS or verb in ("rename-section", "remove-section"):
        return False, key
    if saw_read_flag and not saw_write_flag:
        return False, key
    if verb in _GIT_CONFIG_WRITE_VERBS or saw_write_flag or len(positionals) >= 2:
        return True, key
    return False, key


# TK-57 S7 (STEP-06, REQ-08) / TK-60 STEP-G4 (REQ-09): git argv flags that
# make fetch/pull/push/clone/ls-remote/archive execute an arbitrary program
# on the remote side of the connection (git-fetch(1)/git-push(1)
# "--upload-pack"/"--receive-pack"/"--exec"), including minimal unambiguous
# long-option abbreviations per verb (cli_families.GIT_EXEC_FLAGS). The
# rewriter needs no copy: its closed grammar simply never admits them.
_GIT_EXEC_FLAG_VERBS = frozenset(cli_families.GIT_EXEC_FLAGS)


def _has_git_exec_argv_flag(verb: str, sub_args: list[str]) -> bool:
    return any(cli_families.git_exec_flag_match(verb, tok) for tok in sub_args)


# TK-63 §2.4: `git clean` dry run (`git clean -h`: -n, --[no-]dry-run,
# -d, -x, -X, -q) only lists what would be removed. Closed grammar: every
# token is one of these or a short cluster of the letters n d x X q, and a
# dry run is present. Anything else (-f, -e, -i, --no-dry-run, --, a
# pathspec, an abbreviation) keeps today's verdict; no values are parsed.
_GIT_CLEAN_DRY_RUN_TOKENS = frozenset({"-n", "--dry-run", "-d", "-x", "-X", "-q", "--quiet"})
_RE_GIT_CLEAN_CLUSTER = re.compile(r"-[ndxXq]+")


# Global options taking the next word as their value; the same set the
# subcommand search of _check_high_risk_git skips.
_GIT_TWO_ARG_GLOBALS = frozenset({
    "-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path",
    "--super-prefix", "--config-env",
})


def _git_global_prefix(words: list[str] | None) -> tuple[int, frozenset] | None:
    """Walk the global options of a single `git` command inside the
    engine's closed grammar, as _check_high_risk_git walks today's tokens:
    a two-argument global skips its value, any other `-` word is one word,
    the first other word is the subcommand. Returns (subcommand index or
    -1, the separate-word `-c` values `core.pager=cat` / `core.pager=`,
    key case-insensitive), or None when `words` is None or no git
    command."""
    if words is None or not words or words[0] != "git":
        return None
    no_pager, i = set(), 1
    while i < len(words):
        word = words[i]
        if word in _GIT_TWO_ARG_GLOBALS:
            if word == "-c" and i + 1 < len(words):
                kv = words[i + 1]
                key = kv.split("=", 1)[0]
                if key.casefold() == "core.pager" and kv[len(key):] in ("=cat", "="):
                    no_pager.add(kv)
            i += 2
            continue
        if word.startswith("-"):
            i += 1
            continue
        return i, frozenset(no_pager)
    return -1, frozenset(no_pager)


def _git_clean_dry_run(words: list[str] | None) -> bool:
    """`words`: the shell words of a single command inside the engine's
    closed grammar (None: no exemption); the subcommand after the global
    options is `clean`."""
    prefix = _git_global_prefix(words)
    if prefix is None or prefix[0] == -1 or words[prefix[0]] != "clean":
        return False
    args = words[prefix[0] + 1:]
    if not all(t in _GIT_CLEAN_DRY_RUN_TOKENS or _RE_GIT_CLEAN_CLUSTER.fullmatch(t) for t in args):
        return False
    return any(t == "--dry-run" or (not t.startswith("--") and "n" in t) for t in args)


# ----------------------------------------------------------------------
# TK-70 REQ-02: push forms and protected destination branches
# ----------------------------------------------------------------------

# The fixed protected set is always in force; the global config key
# `protected_branches` only EXTENDS it (owner decision 2026-11-08, INV-07:
# read through actx_lib.config, any error or absence yields the fixed
# pair). Cached per process: a push evaluation reads the config once.
_DEFAULT_PROTECTED_BRANCHES = frozenset({"main", "master"})
_protected_branches_cache = None


def protected_branches() -> frozenset:
    """Branch names a `git push` must not update without confirmation:
    {main, master} union the global `protected_branches` config list."""
    global _protected_branches_cache
    if _protected_branches_cache is None:
        names = set(_DEFAULT_PROTECTED_BRANCHES)
        try:
            from actx_lib import config

            configured = config.load().get("protected_branches")
            if isinstance(configured, list):
                names.update(
                    branch for branch in configured
                    if isinstance(branch, str) and branch
                )
        except Exception:
            pass
        _protected_branches_cache = frozenset(names)
    return _protected_branches_cache


# `git push -h` (git 2.56.0, live 2026-11-08) long-option namespace:
# parse-options.c resolves a unique abbreviation, so `--tag`, `--mir`,
# `--dele`, `--pru`, `--fol` are accepted spellings of the ask forms and
# must match here too. The list holds the option names exactly as git
# prints them (`--[no-]x` entries by the bare name); `--no-<name>` forms
# are negations and deliberately never resolve.
_GIT_PUSH_LONG_OPTIONS = (
    "verbose", "quiet", "repo", "all", "branches", "mirror", "delete",
    "tags", "dry-run", "porcelain", "force", "force-with-lease",
    "force-if-includes", "recurse-submodules", "thin", "receive-pack",
    "exec", "set-upstream", "progress", "prune", "verify", "follow-tags",
    "signed", "atomic", "push-option", "ipv4", "ipv6",
)
# Absolute/mass ref updates and ref deletions: `--mirror` and `--tags`
# are REQ-02 verbatim; `--all`/`--branches` (every local branch, protected
# ones included), `--prune` (deletes remote refs missing locally) and
# `--follow-tags` (a tag push, the semantic sibling of `--tags`) are the
# same class - decided in the TK-70 report, safe direction.
_GIT_PUSH_MASS_ASK = frozenset({
    "all", "branches", "mirror", "delete", "tags", "prune", "follow-tags",
})
# Force forms the exact-spelling loop above cannot see, e.g. the unique
# abbreviation `--force-w` of --force-with-lease (parse-options accepts it;
# any shorter prefix is ambiguous with --force/--force-if-includes).
_GIT_PUSH_FORCE_ASK = frozenset({"force", "force-with-lease"})
# Long options consuming the next token as their value (space form); the
# `=<value>` form carries the value inside the token. Only options with a
# REQUIRED value are listed: `--force-with-lease`/`--signed` take an
# optional value, which parse-options accepts only attached.
_GIT_PUSH_VALUE_LONG = frozenset({
    "repo", "receive-pack", "exec", "push-option", "recurse-submodules",
})


def _git_push_long_name(token: str) -> str | None:
    """The push long option `token` resolves to under parse-options.c:
    exact name first, then a unique prefix. None for an unknown,
    ambiguous or negated (`--no-...`) spelling."""
    if not token.startswith("--"):
        return None
    name = token[2:].split("=", 1)[0]
    if not name or name.startswith("no-"):
        return None
    if name in _GIT_PUSH_LONG_OPTIONS:
        return name
    matches = [opt for opt in _GIT_PUSH_LONG_OPTIONS if opt.startswith(name)]
    return matches[0] if len(matches) == 1 else None


def _git_push_short_letters(body: str) -> tuple[tuple[str, ...], bool]:
    """Short-option cluster letters before the first value-taking option
    (`-o` is push's only one): the rest of such a token is that option's
    attached value, and a bare `-o`/`-qo` consumes the NEXT token. Returns
    (letters, consumes_next_token)."""
    letters = []
    for idx, ch in enumerate(body):
        letters.append(ch)
        if ch == "o":
            return tuple(letters), idx == len(body) - 1
    return tuple(letters), False


def _git_push_positionals(args: list[str]) -> list[str]:
    """`[<repository> [<refspec>...]]` operands of a push argv: every flag
    and its space-form value skipped. A `--` ends option parsing."""
    positionals = []
    i = 0
    n = len(args)
    while i < n:
        tok = _strip_redirection(args[i])
        if not tok:
            i += 1
            continue
        if tok == "--":
            positionals.extend(
                t for t in (_strip_redirection(x) for x in args[i + 1:]) if t
            )
            break
        if tok.startswith("--"):
            if (
                "=" not in tok
                and _git_push_long_name(tok) in _GIT_PUSH_VALUE_LONG
                and i + 1 < n
            ):
                i += 2
                continue
            i += 1
            continue
        if tok.startswith("-") and len(tok) > 1:
            i += 2 if _git_push_short_letters(tok[1:])[1] else 1
            continue
        positionals.append(tok)
        i += 1
    return positionals


def _git_push_refspec_dst(refspec: str) -> str | None:
    """Destination branch name of a push refspec, or None when the refspec
    targets no branch: `src`, `src:dst`, `refs/heads/dst`, `src:refs/heads/
    dst` yield the name; `refs/tags/...` and other non-branch namespaces
    yield None. An empty destination (`src:`) is an invalid refspec git
    itself rejects, so it names nothing."""
    spec = refspec[1:] if refspec.startswith("+") else refspec
    if ":" in spec:
        dst = spec.split(":", 1)[1]
        if not dst:
            return None
    else:
        dst = spec
    if dst.startswith("refs/heads/"):
        dst = dst[len("refs/heads/"):]
    elif dst.startswith("refs/"):
        return None
    return dst or None


def _check_high_risk_git(command: str, raw_tokens: list[str], words: list[str] | None = None) -> SecurityDecision | None:
    tokens = _unwrap_tokens(raw_tokens)
    if not tokens or os.path.basename(tokens[0]) != "git":
        return None

    # Find the git subcommand, skipping multi-argument global flags
    subcmd = None
    subcmd_idx = -1
    idx = 1
    while idx < len(tokens):
        tok = tokens[idx]
        if tok in _GIT_TWO_ARG_GLOBALS:
            idx += 2
            continue
        if tok.startswith("-"):
            idx += 1
            continue
        subcmd = tok
        subcmd_idx = idx
        break
    # TK-57 S7 (STEP-06, REQ-07): git -c / --config-env exec-class config
    # keys ask regardless of value (core.pager, credential.helper, alias.*
    # any value, etc. - a subset of these already asked when the value
    # itself mentioned force/reset/clean/+, kept below as a fallback for
    # unparseable syntax). Only occurrences before the subcommand are
    # git's own global flags - a subcommand-level '-c' (e.g. `git log -c`,
    # the combined-diff flag) is not this class.
    scan_upto = subcmd_idx if subcmd_idx != -1 else len(tokens)
    prefix = _git_global_prefix(words)
    no_pager_values = frozenset() if prefix is None else prefix[1]
    for idx_c in range(1, scan_upto):
        tok_c = tokens[idx_c]
        kv = None
        if tok_c == "-c" and idx_c + 1 < scan_upto:
            kv = tokens[idx_c + 1]
        elif tok_c.startswith("-c") and len(tok_c) > 2 and not tok_c.startswith("--"):
            kv = tok_c[2:]
        elif tok_c == "--config-env" and idx_c + 1 < scan_upto:
            kv = tokens[idx_c + 1]
        elif tok_c.startswith("--config-env="):
            kv = tok_c[len("--config-env="):]
        if kv is None:
            continue
        key = kv.split("=", 1)[0]
        if tok_c == "-c" and kv in no_pager_values:
            # TK-63: an empty or `cat` pager is git's own no-pager setting
            # (git-config(1) core.pager) - the same as `git --no-pager`;
            # only for a single command inside the closed grammar.
            continue
        if _is_git_ask_config_key(key) or (
            ("alias." in kv or "alias " in kv) and ("force" in kv or "reset" in kv or "clean" in kv or "+" in kv)
        ):
            return SecurityDecision(
                decision="ask",
                reason=f"Setting git config key '{key}' can redirect git into executing an arbitrary program",
                category="T6_HIGH_RISK_GIT",
            )

    if subcmd is None or subcmd_idx == -1:
        return None

    sub_args = tokens[subcmd_idx + 1 :]

    # TK-57 S7 (STEP-06, REQ-07): `git config` write of an exec-class key
    # (legacy positional form or the new verb form) - reads (--get/-l/
    # list/get/...) of the same key are unaffected.
    if subcmd == "config":
        is_write, key = _git_config_is_write(sub_args)
        if is_write and key and _is_git_ask_config_key(key):
            return SecurityDecision(
                decision="ask",
                reason=f"Setting git config key '{key}' can redirect git into executing an arbitrary program",
                category="T6_HIGH_RISK_GIT",
            )

    # TK-57 S7 (STEP-06, REQ-08): git exec-class argv flags on a rewritten
    # mutator (fetch/pull/push/clone/ls-remote/archive) ask; the rewriter
    # never admits them (closed grammar), so they also never auto-rewrite.
    if subcmd in _GIT_EXEC_FLAG_VERBS and _has_git_exec_argv_flag(subcmd, sub_args):
        return SecurityDecision(
            decision="ask",
            reason=f"git {subcmd} with an executable-program argv flag (--upload-pack/--receive-pack/--exec) requires human confirmation",
            category="T6_HIGH_RISK_GIT",
        )

    # git push --force / git push -f / git push -qf / git push +ref
    if subcmd == "push":
        for tok in sub_args:
            clean_tok = _strip_redirection(tok)
            if (
                clean_tok in ("--force", "-f", "--force-with-lease")
                or clean_tok.startswith("--force=")
                or clean_tok.startswith("--force-with-lease=")
                or clean_tok.startswith("+")
                or (clean_tok.startswith("-") and not clean_tok.startswith("--") and "f" in clean_tok)
            ):
                return SecurityDecision(
                    decision="ask",
                    reason="Force-pushing to remote git repository requires human confirmation",
                    category="T6_HIGH_RISK_GIT",
                )

        # TK-70 REQ-02: push forms that delete or mass-update remote refs
        # without force - --mirror, --tags (and the tag-push sibling
        # --follow-tags), --delete/-d, --all/--branches, --prune - plus a
        # deleting `:dst` refspec. Long forms match the unique spellings
        # parse-options resolves; short forms are clusters (`-qd`).
        for tok in sub_args:
            clean_tok = _strip_redirection(tok)
            if clean_tok.startswith("--"):
                form = _git_push_long_name(clean_tok)
                if form in _GIT_PUSH_FORCE_ASK:
                    return SecurityDecision(
                        decision="ask",
                        reason="Force-pushing to remote git repository requires human confirmation",
                        category="T6_HIGH_RISK_GIT",
                    )
                if form in _GIT_PUSH_MASS_ASK:
                    return SecurityDecision(
                        decision="ask",
                        reason=f"git push --{form} deletes or mass-updates remote refs and requires human confirmation",
                        category="T6_HIGH_RISK_GIT",
                    )
            elif clean_tok.startswith("-") and not clean_tok.startswith("--"):
                letters = _git_push_short_letters(clean_tok[1:])[0]
                if "d" in letters:
                    return SecurityDecision(
                        decision="ask",
                        reason="Deleting remote refs with 'git push -d/--delete' requires human confirmation",
                        category="T6_HIGH_RISK_GIT",
                    )
            elif clean_tok.startswith(":"):
                return SecurityDecision(
                    decision="ask",
                    reason="Deleting a remote ref via a ':dst' refspec requires human confirmation",
                    category="T6_HIGH_RISK_GIT",
                )

        # A destination branch in the protected set ({main, master} union
        # the config list) asks whatever the refspec spelling: `main`,
        # `src:main`, `refs/heads/main`, `src:refs/heads/main`.
        positionals = _git_push_positionals(sub_args)
        protected = protected_branches()
        for refspec in positionals[1:]:
            dst = _git_push_refspec_dst(refspec)
            if dst is None:
                continue
            if "*" in dst:
                return SecurityDecision(
                    decision="ask",
                    reason="Pushing a wildcard refspec updates several remote refs and requires human confirmation",
                    category="T6_HIGH_RISK_GIT",
                )
            if dst in protected:
                return SecurityDecision(
                    decision="ask",
                    reason=f"Pushing to protected branch '{dst}' requires human confirmation",
                    category="T6_HIGH_RISK_GIT",
                )

    # git reset --hard
    if subcmd == "reset":
        for tok in sub_args:
            clean_tok = _strip_redirection(tok)
            if clean_tok == "--hard" or clean_tok.startswith("--hard="):
                return SecurityDecision(
                    decision="ask",
                    reason="Hard reset discards uncommitted changes and requires human confirmation",
                    category="T6_HIGH_RISK_GIT",
                )

    # git clean with -x / -X (removing ignored files)
    if subcmd == "clean" and not _git_clean_dry_run(words):
        for tok in sub_args:
            clean_tok = _strip_redirection(tok)
            if clean_tok in ("-x", "-X", "-fx", "-xf", "-fdx", "-dxf", "-fxd") or (
                clean_tok.startswith("-") and not clean_tok.startswith("--") and ("x" in clean_tok or "X" in clean_tok)
            ):
                return SecurityDecision(
                    decision="ask",
                    reason="Hard cleaning ignored workspace files requires human confirmation",
                    category="T6_HIGH_RISK_GIT",
                )

    # git branch -D / -d -f / -f -d / -df / -fd / --delete --force
    if subcmd == "branch":
        for tok in sub_args:
            clean_tok = _strip_redirection(tok).strip("'\"")
            if (
                clean_tok == "-D"
                or (clean_tok.startswith("-") and not clean_tok.startswith("--") and "D" in clean_tok)
                or clean_tok in ("-df", "-fd")
            ):
                return SecurityDecision(
                    decision="ask",
                    reason="Force-deleting git branch requires human confirmation",
                    category="T6_HIGH_RISK_GIT",
                )
        if ("-d" in sub_args or "--delete" in sub_args) and ("-f" in sub_args or "--force" in sub_args):
            return SecurityDecision(
                decision="ask",
                reason="Force-deleting git branch requires human confirmation",
                category="T6_HIGH_RISK_GIT",
            )

    # git checkout . / git checkout -- . / git checkout -- * / whole tree pathspecs
    if subcmd == "checkout":
        if any(tok.strip("'\"") in (".", "*", ":(top)", ":(top)**", ":/") or tok.strip("'\"").startswith(":(top)") for tok in sub_args):
            return SecurityDecision(
                decision="ask",
                reason="Discarding local changes via 'git checkout' requires human confirmation",
                category="T6_HIGH_RISK_GIT",
            )

    # git restore . / git restore -- . / git restore -- * / whole tree pathspecs
    if subcmd == "restore":
        if any(tok.strip("'\"") in (".", "*", ":(top)", ":(top)**", ":/") or tok.strip("'\"").startswith(":(top)") for tok in sub_args):
            return SecurityDecision(
                decision="ask",
                reason="Discarding local changes via 'git restore' requires human confirmation",
                category="T6_HIGH_RISK_GIT",
            )

    return None
