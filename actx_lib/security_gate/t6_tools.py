"""actx security gate - T6: cargo / npm / swiftformat / gradlew / cloud-infra
CLI mutations (ask confirmation) (TK-59 split).

Body unchanged from the pre-split monolith - see tools/ast_identity_check.py.
"""

import os

from actx_lib import cli_families

from .common import SecurityDecision, _unwrap_tokens
from .t5_supply import _first_positional



# ----------------------------------------------------------------------
# T6: High-Risk Cargo Operations (Ask Confirmation)
# ----------------------------------------------------------------------

_CARGO_REGISTRY_MUTATE = frozenset({"publish", "yank", "owner", "login", "logout"})
_CARGO_GATE_1ARG_FLAGS = frozenset({
    "-q", "--quiet", "-v", "-vv", "-vvv", "--verbose",
    "--offline", "--locked", "--frozen",
})
_CARGO_GATE_2ARG_FLAGS = frozenset({
    "--color", "--config", "-C", "-Z", "--manifest-path", "--target-dir",
})


def _parse_cargo_subcommand(raw_tokens: list[str]):
    """Extracts (subcmd, sub_args) for cargo commands, skipping wrapper and global options."""
    tokens = _unwrap_tokens(raw_tokens)
    if not tokens or os.path.basename(tokens[0]) != "cargo":
        return None, []

    idx = 1
    n = len(tokens)
    while idx < n:
        tok = tokens[idx]
        if tok == "--":
            return None, []
        if tok.startswith("+"):
            idx += 1
            continue
        if tok in _CARGO_GATE_1ARG_FLAGS:
            idx += 1
            continue
        if tok in _CARGO_GATE_2ARG_FLAGS:
            idx += 2
            continue
        if tok.startswith("--color=") or tok.startswith("--config=") or tok.startswith("-C=") or tok.startswith("-Z="):
            idx += 1
            continue
        if tok.startswith("-"):
            idx += 1
            continue
        subcmd = tok
        sub_args = tokens[idx + 1 :]
        return subcmd, sub_args
    return None, []


def _check_high_risk_cargo(command: str, raw_tokens: list[str]) -> SecurityDecision | None:
    subcmd, sub_args = _parse_cargo_subcommand(raw_tokens)
    if subcmd is None:
        return None

    if subcmd == "clean":
        return SecurityDecision(
            decision="ask",
            reason="Executing cargo clean deletes build artifacts and caches, requiring human confirmation",
            category="T6_HIGH_RISK_CARGO",
        )
    if subcmd in _CARGO_REGISTRY_MUTATE:
        return SecurityDecision(
            decision="ask",
            reason=f"Executing cargo {subcmd} modifies remote registry state or credentials, requiring human confirmation",
            category="T6_HIGH_RISK_CARGO",
        )
    # TK-51 (user policy 2026-09-05): ANY cargo install asks — not just the
    # historical --force overwrite. `cargo add` adds registry dependencies to
    # Cargo.toml, the same install class. build/test/check merely resolve the
    # lockfile and stay allow (primary-semantics boundary, wave-2 plan §7).
    if subcmd == "install":
        return SecurityDecision(
            decision="ask",
            reason="cargo install downloads, builds and installs crates.io binaries, requiring human confirmation",
            category="T6_HIGH_RISK_CARGO",
        )
    if subcmd == "add":
        return SecurityDecision(
            decision="ask",
            reason="cargo add adds registry dependencies to Cargo.toml, requiring human confirmation",
            category="T6_HIGH_RISK_CARGO",
        )

    return None


# ----------------------------------------------------------------------
# T6: swiftformat mutating mode (Ask Confirmation) — N-F11
# ----------------------------------------------------------------------

_SWIFTFORMAT_READONLY_FLAGS = ("--lint", "--dryrun", "--dry-run", "--version", "--help")


def _check_swiftformat(command: str, raw_tokens: list[str]) -> SecurityDecision | None:
    """Bare `swiftformat` (or with paths/flags but no lint/dry mode) rewrites
    Swift source files in place - a mutator. The absence of a lint/dry flag
    is not expressible in the T6 verb table, hence this dedicated check in
    the `_check_high_risk_cargo` style."""
    tokens = _unwrap_tokens(raw_tokens)
    if not tokens or os.path.basename(tokens[0]) != "swiftformat":
        return None
    if any(tok in _SWIFTFORMAT_READONLY_FLAGS for tok in tokens[1:]):
        return None
    return SecurityDecision(
        decision="ask",
        reason="Bare swiftformat rewrites Swift files in place, requiring human confirmation",
        category="T6_HIGH_RISK_SWIFTFORMAT",
    )


# ----------------------------------------------------------------------
# T6: High-Risk npm Registry Operations (Ask Confirmation) — TK-51
# ----------------------------------------------------------------------

_NPM_REGISTRY_MUTATE = frozenset({"owner", "access", "org", "team"})


def _check_high_risk_npm(command: str, raw_tokens: list[str]) -> SecurityDecision | None:
    """T6 registry-mutation gate for npm, precedent ``_check_high_risk_cargo``.

    `npm publish` uploads to the public registry; `owner`/`access`/`org`/
    `team` mutate registry ownership and access metadata — all ask.
    `publish --dry-run` performs no upload and stays allow. `npm token ...`
    is denied earlier by the T1 credential gate (explicit regression test).
    """
    tokens = _unwrap_tokens(raw_tokens)
    if not tokens or os.path.basename(tokens[0]) != "npm":
        return None

    vi = _first_positional(tokens)
    if vi is None:
        return None
    verb = tokens[vi]

    if verb == "publish":
        if "--dry-run" in tokens[vi + 1:]:
            return None
        return SecurityDecision(
            decision="ask",
            reason="npm publish uploads a package to the public registry, requiring human confirmation",
            category="T6_HIGH_RISK_NPM",
        )
    if verb in _NPM_REGISTRY_MUTATE:
        return SecurityDecision(
            decision="ask",
            reason=f"npm {verb} mutates registry ownership or access metadata, requiring human confirmation",
            category="T6_HIGH_RISK_NPM",
        )
    return None


# ----------------------------------------------------------------------
# T6: High-Risk Cloud/Infra CLI Mutations (Ask Confirmation)
# ----------------------------------------------------------------------

# Declarative verb table: tool -> tuple of specs; each spec is a token
# subsequence that must appear in order among the command arguments.
# A spec ending in a "--" token additionally requires that flag verbatim
# (e.g. vercel deploy --prod; preview deploys stay allow).
# Token equality is exact: "--rm" never matches "rm", "delete-target"
# never matches "delete".
# Known false positive (accepted, ask-tier): an argument value equal to a
# spec verb (e.g. namespace "delete" in `kubectl -n delete get pods`)
# triggers an ask; rare, and the human resolves it.
#
# Cloud/infra family specs are generated from the declarative cli_families
# table (TK-39): the 6 pre-existing cloud entries live there byte-identically;
# flyctl was new in TK-39. docker moved to FAMILIES in TK-41, kubectl/helm in
# TK-40 and terraform in TK-43 (N-F1): a stale entry here would shadow the
# family ask_specs through the setdefault loop below — a record must live in
# exactly one place. Non-cloud entries stay verbatim below.
_T6_NON_CLOUD_ASK_TABLE: dict[str, tuple[tuple[str, ...], ...]] = {
    "simctl": (("erase",), ("delete",)),
    "flutter": (("clean",),),
    "xcodebuild": (("clean",),),
    "pod": (("deintegrate",),),
}

T6_ASK_TABLE: dict[str, tuple[tuple[str, ...], ...]] = dict(_T6_NON_CLOUD_ASK_TABLE)
for _head, _spec in cli_families.FAMILIES.items():
    T6_ASK_TABLE.setdefault(_head, _spec["ask_specs"])
del _head, _spec


def _check_high_risk_tools(command: str, raw_tokens: list[str]) -> SecurityDecision | None:
    tokens = _unwrap_tokens(raw_tokens)
    if not tokens:
        return None
    head = os.path.basename(tokens[0])
    specs = T6_ASK_TABLE.get(head)
    if specs is None:
        return None

    args = tokens[1:]
    for spec in specs:
        # Ordered subsequence scan: interleaved flags/args are skipped;
        # spec tokens must match exactly and in order. A trailing "--"
        # element is a mandatory flag matched by the same exact equality.
        cursor = 0
        for spec_tok in spec:
            while cursor < len(args) and args[cursor] != spec_tok:
                cursor += 1
            if cursor == len(args):
                break
            cursor += 1
        else:
            return SecurityDecision(
                decision="ask",
                reason=f"Executing {head} {' '.join(spec)} requires human confirmation",
                category="T6_HIGH_RISK_" + head.upper(),
            )

    return None


def _check_gradlew(command: str, raw_tokens: list[str]) -> SecurityDecision | None:
    """T6 ask for gradlew publish-class tasks (TK-55 F5), precedent
    ``_check_high_risk_cargo``.

    The exact-token T6 verb table cannot express ``:module:publish`` task
    addressing, so positional task tokens are classified by
    cli_families.gradle_task_class (last ``:``-segment): a
    publish/clean-class marker asks. RO bases and unknown tasks stay
    allow - the rewriter only rewrites an all-RO argv and unknown verbs
    defer to the native permission layer (the gate is fail-open).
    Flag handling follows the shared gradle tables: value flags skip
    their value token, ``-P*``/``-D*`` attached forms and boolean flags
    skip whole, and an unrecognized ``-`` token is skipped too - an
    unknown flag is a reason for neither an ask nor a scan stop."""
    tokens = _unwrap_tokens(raw_tokens)
    if not tokens or os.path.basename(tokens[0]) != "gradlew":
        return None
    idx = 1
    while idx < len(tokens):
        tok = tokens[idx]
        if tok in cli_families.GRADLE_VALUE_FLAGS:
            idx += 2  # the flag and its separate value token
            continue
        if tok.startswith(cli_families.GRADLE_ATTACHED_VALUE_PREFIXES):
            idx += 1  # -Pprop=v / -Dprop=v: the value stays inside the token
            continue
        if tok.startswith("-"):
            idx += 1  # bool or unknown flag: skip, keep scanning
            continue
        if cli_families.gradle_task_class(tok) == "ask":
            return SecurityDecision(
                decision="ask",
                reason=f"Executing gradlew {tok} mutates remote artifacts or deletes build outputs, requiring human confirmation",
                category="T6_HIGH_RISK_GRADLEW",
            )
        idx += 1
    return None
