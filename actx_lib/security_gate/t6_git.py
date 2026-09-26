"""actx security gate - T6: high-risk git mutations (ask confirmation)
(TK-59 split).

Body unchanged from the pre-split monolith - see tools/ast_identity_check.py.
"""

import fnmatch
import os

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


def _check_high_risk_git(command: str, raw_tokens: list[str]) -> SecurityDecision | None:
    tokens = _unwrap_tokens(raw_tokens)
    if not tokens or os.path.basename(tokens[0]) != "git":
        return None

    # Find the git subcommand, skipping multi-argument global flags
    subcmd = None
    subcmd_idx = -1
    idx = 1
    two_arg_flags = {
        "-C",
        "-c",
        "--git-dir",
        "--work-tree",
        "--namespace",
        "--exec-path",
        "--super-prefix",
        "--config-env",
    }
    while idx < len(tokens):
        tok = tokens[idx]
        if tok in two_arg_flags:
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
    if subcmd == "clean":
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
