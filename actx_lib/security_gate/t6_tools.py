"""actx security gate - T6: cargo / npm / swiftformat / gradlew / cloud-infra
CLI mutations (ask confirmation) (TK-59 split).

Bodies are the pre-split monolith's except where a later wave changed
behaviour deliberately (TK-63 dry-run grammars, TK-70 REQ-03 external
mutations and the `=`-spelling table match) - see tools/ast_identity_check.py
and ALLOWED_CHANGED_DEFS there.
"""

import os
import re
import shlex

from actx_lib import cli_families

from .common import SecurityDecision, _unwrap_tokens
from .t5_supply import _first_positional
from .t6_git import _check_high_risk_git
from .t6_sql import _check_sql



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


# TK-63 §2.4: `cargo publish -n|--dry-run` performs every check without
# uploading (`cargo publish --help`). Closed grammar: `publish` directly
# after `cargo`, every other token from these sets; a -n/--dry-run consumed
# as an option value does not count. Anything else keeps the ask.
_CARGO_PUBLISH_DRY_RUN_FLAGS = frozenset({"-n", "--dry-run"})
_CARGO_PUBLISH_BOOL_FLAGS = frozenset({
    "--allow-dirty", "--no-verify", "--locked", "--offline", "--frozen",
    "-q", "--quiet", "-v", "--verbose", "--all-features",
    "--no-default-features", "--keep-going",
})
_CARGO_PUBLISH_VALUE_FLAGS = frozenset({"--registry", "-p", "--package"})


def _cargo_publish_dry_run(words: list[str] | None) -> bool:
    """`words`: the shell words of a single command inside the engine's
    closed grammar (None: no exemption)."""
    tokens = words
    if tokens is None or len(tokens) < 2 or tokens[0] != "cargo" or tokens[1] != "publish":
        return False
    dry_run = False
    i = 2
    while i < len(tokens):
        tok = tokens[i]
        if tok in _CARGO_PUBLISH_DRY_RUN_FLAGS:
            dry_run = True
        elif tok in _CARGO_PUBLISH_VALUE_FLAGS:
            if i + 1 >= len(tokens):
                return False
            i += 1  # the value token, whatever it looks like
        elif tok in _CARGO_PUBLISH_BOOL_FLAGS:
            pass
        elif not ("=" in tok and tok.split("=", 1)[0] in _CARGO_PUBLISH_VALUE_FLAGS):
            return False
        i += 1
    return dry_run


def _check_high_risk_cargo(command: str, raw_tokens: list[str], words: list[str] | None = None) -> SecurityDecision | None:
    subcmd, sub_args = _parse_cargo_subcommand(raw_tokens)
    if subcmd is None:
        return None

    if subcmd == "clean":
        return SecurityDecision(
            decision="ask",
            reason="Executing cargo clean deletes build artifacts and caches, requiring human confirmation",
            category="T6_HIGH_RISK_CARGO",
        )
    if subcmd == "publish" and _cargo_publish_dry_run(words):
        return None
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
# TK-70 REQ-03: before the match a token starting with "-" and carrying
# "=" is reduced to its flag part (`--prod=false` -> `--prod`,
# `-out=false` -> `-out`); the value never becomes a scan token and the
# flag is never removed. This is the only normalization - whether a value
# means on or off belongs to the tool's own parser (vercel reads
# `--prod=false` as prod; bq's dry-run literal is handled by its
# predicate), so every `=`-spelling counts as the flag being present
# (safe side).
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
    # TK-70 REQ-03: heads without a rewrite family - ask only, never
    # rewritten (INV-05). Firebase colon-form subcommands are single tokens.
    "firebase": (("deploy",), ("functions:secrets:set",)),
    "gsutil": (("rm",),),
    "twine": (("upload",),),
    "gem": (("push",),),
    "poetry": (("publish",),),
    "pnpm": (("publish",),),
    "yarn": (("publish",),),
    "bun": (("publish",),),
    "uv": (("publish",),),
    # Heroku's documented spelling is the colon form; the two-token form
    # stays as the REQ-03 spec. `config:unset` is the deletion sibling.
    "heroku": (("config", "set"), ("config:set",), ("config:unset",)),
    # Stripe CLI verbs that change remote payment objects.
    "stripe": (("create",), ("update",), ("delete",), ("cancel",),
               ("refund",), ("capture",), ("confirm",)),
}

T6_ASK_TABLE: dict[str, tuple[tuple[str, ...], ...]] = dict(_T6_NON_CLOUD_ASK_TABLE)
for _head, _spec in cli_families.FAMILIES.items():
    T6_ASK_TABLE.setdefault(_head, _spec["ask_specs"])
del _head, _spec

# TK-70: an alias for the gate-table lookup only (`fly deploy` asks as
# flyctl). The rewriter has no `fly` family, so its behaviour is unchanged.
_T6_HEAD_ALIASES = {"fly": "flyctl"}


def _t6_table_token(token: str) -> str:
    """The table-match spelling of one argv token: a `-`-prefixed token
    carrying `=` keeps only its flag part (`--prod=false` -> `--prod`);
    every other token is unchanged."""
    if token.startswith("-") and "=" in token:
        return token.split("=", 1)[0]
    return token


# ----------------------------------------------------------------------
# TK-70 REQ-03: external-mutation predicates (heads whose ask condition is
# not a fixed token subsequence, or whose parser has a semantic exception)
# ----------------------------------------------------------------------

def _t6_ask(head: str, reason: str) -> SecurityDecision:
    return SecurityDecision(
        decision="ask",
        reason=reason,
        category="T6_HIGH_RISK_" + head.upper(),
    )


# aws/az: default-ask; allow only when every operand after the service name
# starts with an observational verb. Global value-taking options are from
# `aws help` (AWS CLI v2: --endpoint-url, --output, --query, --profile,
# --region, --color, --ca-bundle, --cli-read-timeout, --cli-connect-timeout,
# --cli-binary-format, --cli-error-format) and `az --help` (--output/-o,
# --query, --subscription); every other `-` token is a one-token boolean.
_AWS_GLOBAL_VALUE_FLAGS = frozenset({
    "--endpoint-url", "--output", "--query", "--profile", "--region",
    "--color", "--ca-bundle", "--cli-read-timeout",
    "--cli-connect-timeout", "--cli-binary-format", "--cli-error-format",
})
_AZ_GLOBAL_VALUE_FLAGS = frozenset({
    "--output", "-o", "--query", "--subscription",
})
_AWS_AZ_RO_PREFIX = re.compile(
    r"^(?:get|list|describe|show|head|ls|view|check|status|whoami|help|version)",
    re.IGNORECASE,
)


def _aws_az_operands(args: list[str], value_flags: frozenset) -> list[str]:
    """Positional operands of an aws/az argv: flags and their space-form
    values are skipped; `--` ends option parsing."""
    operands = []
    i = 0
    while i < len(args):
        tok = args[i]
        if tok == "--":
            operands.extend(args[i + 1:])
            break
        if tok.startswith("-") and tok != "-":
            if "=" not in tok and tok in value_flags and i + 1 < len(args):
                i += 1
            i += 1
            continue
        operands.append(tok)
        i += 1
    return operands


def _aws_az_mutation(head: str, args: list[str]) -> bool:
    """The first operand is the service/namespace; any later operand that
    does not start with an observational verb marks the command as a
    mutation (rare false asks are the safe direction, A4)."""
    value_flags = _AWS_GLOBAL_VALUE_FLAGS if head == "aws" else _AZ_GLOBAL_VALUE_FLAGS
    operands = _aws_az_operands(args, value_flags)
    return any(not _AWS_AZ_RO_PREFIX.match(tok) for tok in operands[1:])


# curl: data/form/upload flags ask in every spelling; -X/--request asks when
# its method mutates. `curl --help all` (curl 8.x) is the short-option
# source: the data/method letters are checked before the value-consuming
# table, so attached values (-dfoo, -XPOST) still count while `-Hd` (header
# value "d") does not.
_CURL_DATA_LONG_FLAGS = frozenset({
    "--data", "--data-ascii", "--data-binary", "--data-raw",
    "--data-urlencode", "--form", "--form-string", "--json",
    "--upload-file",
})
_CURL_REQUEST_LONG_FLAGS = frozenset({"--request"})
_CURL_VALUE_SHORT_LETTERS = frozenset("AbcCdDeEFHKmoPQrtTuUwxXyYz")
_MUTATING_HTTP_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _short_cluster_forms(body: str, tracked: str, value_letters: frozenset):
    """The first tracked letter of a short-option cluster and its attached
    rest; scanning stops at the first value-taking letter, whose rest is
    that option's attached value (`-Hd` is header "d", not -d)."""
    for idx, ch in enumerate(body):
        if ch in tracked:
            return ch, body[idx + 1:]
        if ch in value_letters:
            return None
    return None


def _method_is_mutating(method: str) -> bool:
    return method.lstrip("=").strip().upper() in _MUTATING_HTTP_METHODS


def _curl_asks(args: list[str]) -> bool:
    i = 0
    while i < len(args):
        tok = args[i]
        if tok.startswith("--"):
            name, sep, value = tok.partition("=")
            if name in _CURL_DATA_LONG_FLAGS:
                return True
            if name in _CURL_REQUEST_LONG_FLAGS:
                if sep:
                    if _method_is_mutating(value):
                        return True
                elif i + 1 < len(args) and _method_is_mutating(args[i + 1]):
                    return True
                i += 1
        elif tok.startswith("-") and len(tok) > 1:
            found = _short_cluster_forms(tok[1:], "dFTX", _CURL_VALUE_SHORT_LETTERS)
            if found is not None:
                letter, rest = found
                if letter != "X":
                    return True
                method = rest
                if not method and i + 1 < len(args):
                    method = args[i + 1]
                if _method_is_mutating(method):
                    return True
        i += 1
    return False


# wget: GNU getopt_long resolves a unique long-option prefix, so the
# minimal unambiguous prefix of the two post options (both data flags, so
# their shared prefix is safe) and of --method match as well. GNU wget has
# no short spelling for any of them. A non-GET --method asks, GET does not.
_WGET_DATA_LONG_FLAGS = ("--post-data", "--post-file")
_WGET_METHOD_LONG_FLAG = "--method"
_WGET_DATA_MIN_PREFIX = "--post"
_WGET_METHOD_MIN_PREFIX = "--meth"


def _wget_form(name: str) -> str | None:
    if len(name) >= len(_WGET_DATA_MIN_PREFIX) and any(
        flag.startswith(name) for flag in _WGET_DATA_LONG_FLAGS
    ):
        return "data"
    if len(name) >= len(_WGET_METHOD_MIN_PREFIX) and _WGET_METHOD_LONG_FLAG.startswith(name):
        return "method"
    return None


def _wget_asks(args: list[str]) -> bool:
    i = 0
    while i < len(args):
        tok = args[i]
        if tok.startswith("--"):
            name, sep, value = tok.partition("=")
            form = _wget_form(name)
            if form == "data":
                return True
            if form == "method":
                method = value if sep else (args[i + 1] if i + 1 < len(args) else "")
                if method.lstrip("=").strip().upper() not in ("", "GET"):
                    return True
                i += 1 if sep else 2
                continue
        i += 1
    return False


# mysql -e/--execute and mongosh --eval payloads: a mutating statement or
# JS call in the inline payload asks. SQL verbs are word-boundary matched,
# case-insensitively; the mongosh pattern covers `db.<collection>.<verb>`
# and the getCollection(...) accessor form.
_MYSQL_SQL_MUTATORS = re.compile(
    r"\b(?:INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|REPLACE|TRUNCATE|SET"
    r"|GRANT|REVOKE)\b",
    re.IGNORECASE,
)
# mysql short options consuming a value (mysql --help): -u user, -h host,
# -p password, -P port, -S socket, -D database, -e execute, -O variable.
_MYSQL_VALUE_SHORT_LETTERS = frozenset("uhpPSDeO")
_MONGOSH_JS_MUTATORS = re.compile(
    r"\bdb\b[^\n;]*\.(?:insert|insertOne|insertMany|update|updateOne"
    r"|updateMany|replaceOne|delete|deleteOne|deleteMany|drop|dropDatabase"
    r"|renameCollection|bulkWrite)\b",
    re.IGNORECASE,
)


def _mysql_eval_payload(args: list[str]) -> str | None:
    i = 0
    while i < len(args):
        tok = args[i]
        if tok == "--execute" or tok.startswith("--execute="):
            if "=" in tok:
                return tok.split("=", 1)[1]
            return args[i + 1] if i + 1 < len(args) else ""
        if tok.startswith("-") and not tok.startswith("--") and len(tok) > 1:
            found = _short_cluster_forms(tok[1:], "e", _MYSQL_VALUE_SHORT_LETTERS)
            if found is not None:
                _, rest = found
                return rest if rest else (args[i + 1] if i + 1 < len(args) else "")
        i += 1
    return None


def _mongosh_eval_payload(args: list[str]) -> str | None:
    i = 0
    while i < len(args):
        tok = args[i]
        if tok == "--eval" or tok.startswith("--eval="):
            if "=" in tok:
                return tok.split("=", 1)[1]
            return args[i + 1] if i + 1 < len(args) else ""
        i += 1
    return None


# Wrapper targets: make, npm run/run-script and just recipes whose name
# carries a deploy/release/publish marker. For make and just every
# positional is scanned (the first may be a value of `-f`/`-C`; a marker on
# a recipe argument is the safe-direction false positive), for npm the
# token right after `run`/`run-script`.
_DEPLOY_MARKERS = ("deploy", "release", "publish")


def _has_deploy_marker(token: str) -> bool:
    low = token.lower()
    return any(marker in low for marker in _DEPLOY_MARKERS)


def _positional_marker_asks(args: list[str]) -> bool:
    return any(
        not tok.startswith("-") and "=" not in tok and _has_deploy_marker(tok)
        for tok in args
    )


def _npm_run_target_asks(args: list[str]) -> bool:
    for idx, tok in enumerate(args):
        if tok not in ("run", "run-script"):
            continue
        for candidate in args[idx + 1:]:
            if candidate.startswith("-"):
                continue
            return _has_deploy_marker(candidate)
        return False
    return False


# gh api: the whole mutating HTTP class - a mutating -X/--method/--request
# or any POST-implying field/input flag asks. -R/--repo/--hostname are the
# only value-taking globals before the `api` verb; inside, -H/-q are the
# value-taking shorts that stop a cluster scan.
_GH_API_METHOD_LONG_FLAGS = frozenset({"--method", "--request"})
_GH_API_POST_LONG_FLAGS = frozenset({"--field", "--raw-field", "--input"})
_GH_API_VALUE_SHORT_LETTERS = frozenset("Hq")


def _gh_api_args(args: list[str]) -> list[str] | None:
    i = 0
    while i < len(args):
        tok = args[i]
        if tok in ("-R", "--repo", "--hostname"):
            i += 2
            continue
        if tok.startswith("-"):
            i += 1
            continue
        return args[i + 1:] if tok == "api" else None
    return None


def _gh_api_mutation(args: list[str]) -> bool:
    api_args = _gh_api_args(args)
    if api_args is None:
        return False
    i = 0
    while i < len(api_args):
        tok = api_args[i]
        if tok.startswith("--"):
            name, sep, value = tok.partition("=")
            if name in _GH_API_POST_LONG_FLAGS:
                return True
            if name in _GH_API_METHOD_LONG_FLAGS:
                method = value if sep else (api_args[i + 1] if i + 1 < len(api_args) else "")
                if _method_is_mutating(method):
                    return True
                i += 1
        elif tok.startswith("-") and len(tok) > 1:
            found = _short_cluster_forms(tok[1:], "fFX", _GH_API_VALUE_SHORT_LETTERS)
            if found is not None:
                letter, rest = found
                if letter in ("f", "F"):
                    return True
                method = rest
                if not method and i + 1 < len(api_args):
                    method = api_args[i + 1]
                if _method_is_mutating(method):
                    return True
        i += 1
    return False


# bq: query/rm/update ask; the only exemption is a dry-run query, and it is
# a POSITIVE list (E-007): a bare --dry_run/--dry-run or =true|=1|=t (case-
# insensitive). Every other value - including false/0/f/no/n/off - and the
# absence of the flag ask.
_BQ_MUTATING_VERBS = frozenset({"query", "rm", "update"})
_BQ_DRY_RUN_NAMES = frozenset({"--dry_run", "--dry-run"})
_BQ_DRY_RUN_TRUE = frozenset({"", "true", "1", "t"})


def _bq_query_asks(args: list[str]) -> bool:
    verb = next((tok for tok in args if tok in _BQ_MUTATING_VERBS), None)
    if verb is None:
        return False
    if verb != "query":
        return True
    dry_run = None
    for tok in args:
        name, sep, value = tok.partition("=")
        if name in _BQ_DRY_RUN_NAMES:
            dry_run = value if sep else ""
    if dry_run is None:
        return True
    return dry_run.strip().lower() not in _BQ_DRY_RUN_TRUE


def _check_high_risk_tools(command: str, raw_tokens: list[str]) -> SecurityDecision | None:
    tokens = _unwrap_tokens(raw_tokens)
    if not tokens:
        return None
    head = os.path.basename(tokens[0])
    lookup = _T6_HEAD_ALIASES.get(head, head)
    args = tokens[1:]

    specs = T6_ASK_TABLE.get(lookup)
    if specs:
        scan_args = [_t6_table_token(tok) for tok in args]
        for spec in specs:
            # Ordered subsequence scan: interleaved flags/args are skipped;
            # spec tokens must match exactly and in order. A trailing "--"
            # element is a mandatory flag matched by the same exact equality.
            cursor = 0
            for spec_tok in spec:
                while cursor < len(scan_args) and scan_args[cursor] != spec_tok:
                    cursor += 1
                if cursor == len(scan_args):
                    break
                cursor += 1
            else:
                return SecurityDecision(
                    decision="ask",
                    reason=f"Executing {lookup} {' '.join(spec)} requires human confirmation",
                    category="T6_HIGH_RISK_" + lookup.upper(),
                )

    if lookup in ("aws", "az"):
        if _aws_az_mutation(lookup, args):
            return _t6_ask(
                lookup,
                f"{lookup} command with a mutating verb requires human confirmation",
            )
    elif lookup == "curl":
        if _curl_asks(args):
            return _t6_ask(
                "curl",
                "curl request that sends data or uses a mutating method requires human confirmation",
            )
    elif lookup == "wget":
        if _wget_asks(args):
            return _t6_ask(
                "wget",
                "wget request that sends data or uses a non-GET method requires human confirmation",
            )
    elif lookup == "mysql":
        payload = _mysql_eval_payload(args)
        if payload is not None and _MYSQL_SQL_MUTATORS.search(payload):
            return _t6_ask(
                "mysql",
                "mysql -e/--execute payload carries a mutating SQL statement and requires human confirmation",
            )
    elif lookup == "mongosh":
        payload = _mongosh_eval_payload(args)
        if payload is not None and _MONGOSH_JS_MUTATORS.search(payload):
            return _t6_ask(
                "mongosh",
                "mongosh --eval payload carries a mutating JavaScript call and requires human confirmation",
            )
    elif lookup == "make":
        if _positional_marker_asks(args):
            return _t6_ask(
                "make",
                "make target with a deploy/release/publish marker requires human confirmation",
            )
    elif lookup == "npm":
        if _npm_run_target_asks(args):
            return _t6_ask(
                "npm",
                "npm run script with a deploy/release/publish marker requires human confirmation",
            )
    elif lookup == "just":
        if _positional_marker_asks(args):
            return _t6_ask(
                "just",
                "just recipe with a deploy/release/publish marker requires human confirmation",
            )
    elif lookup == "gh":
        if _gh_api_mutation(args):
            return _t6_ask(
                "gh",
                "gh api request with a mutating method or body field requires human confirmation",
            )
    elif lookup == "bq":
        if _bq_query_asks(args):
            return _t6_ask(
                "bq",
                "bq command mutates remote state and requires human confirmation",
            )

    return None


# TK-63 §2.4: closed grammar of local-only tasks that carry an ask marker.
# signingReport prints the signing configs (developer.android.com/studio/
# publish/app-signing); publishToMavenLocal and
# publish<Name>PublicationToMavenLocal write only the local Maven cache
# (docs.gradle.org/current/userguide/publishing_maven.html, "Tasks");
# assemble<Variant>Release / bundle<Variant>Release build local APK/AAB
# outputs (developer.android.com/build/build-variants).
# A marker inside the variant/publication name keeps the ask
# (assembleSignedRelease, publishReleasePublicationToMavenLocal). Limit:
# any gradle task can run build-script logic, as allowed assembleDebug can.
_RE_GRADLE_MAVEN_LOCAL = re.compile(r"publish([a-z0-9]*)publicationtomavenlocal")


def _gradle_local_task(token: str) -> bool:
    segment = token.rsplit(":", 1)[-1].lower()
    if segment in ("signingreport", "publishtomavenlocal"):
        return True
    m = _RE_GRADLE_MAVEN_LOCAL.fullmatch(segment)
    if m:
        middle = m.group(1)
    else:
        prefix = next((p for p in ("assemble", "bundle") if segment.startswith(p)), None)
        if prefix is None or not segment.endswith("release") or len(segment) < len(prefix) + len("release"):
            return False
        middle = segment[len(prefix):-len("release")]
    return not any(marker in middle for marker in cli_families.GRADLE_ASK_MARKERS)


def _gradle_local_words(words: list[str] | None) -> set:
    """Positional task words of a single gradlew command inside the engine's
    closed grammar that _gradle_local_task exempts; empty when `words` is
    None. Flags are walked as in _check_gradlew."""
    out = set()
    if words is None or os.path.basename(words[0]) != "gradlew":
        return out
    idx = 1
    while idx < len(words):
        word = words[idx]
        if word in cli_families.GRADLE_VALUE_FLAGS:
            idx += 2
            continue
        if not word.startswith("-") and _gradle_local_task(word):
            out.add(word)
        idx += 1
    return out


def _check_gradlew(command: str, raw_tokens: list[str], words: list[str] | None = None) -> SecurityDecision | None:
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
    local_tasks = _gradle_local_words(words)
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
        if tok in local_tasks:
            idx += 1
            continue
        if cli_families.gradle_task_class(tok) == "ask":
            return SecurityDecision(
                decision="ask",
                reason=f"Executing gradlew {tok} mutates remote artifacts or deletes build outputs, requiring human confirmation",
                category="T6_HIGH_RISK_GRADLEW",
            )
        idx += 1
    return None


def looks_irreversible(command: str) -> bool:
    """Best-effort mirror of the T6 dispatch for the gate's failure paths
    (TK-70 REQ-04): True when any T6 checker would ask on any chunk of
    `command`, or when this function itself fails. Tokenization is
    best-effort (shlex in a try); the engine's closed-grammar exemptions
    are not available here, so each checker runs in its stricter form
    (None words) - the safe side on an error path."""
    try:
        if not isinstance(command, str):
            return True
        from .engine import _split_into_chunks

        for chunk in _split_into_chunks(command):
            chunk = chunk.strip()
            if not chunk:
                continue
            tokens = shlex.split(chunk, posix=True)
            if not tokens:
                continue
            if _check_high_risk_git(chunk, tokens, None):
                return True
            if _check_high_risk_cargo(chunk, tokens, None):
                return True
            if _check_swiftformat(chunk, tokens):
                return True
            if _check_high_risk_npm(chunk, tokens):
                return True
            if _check_high_risk_tools(chunk, tokens):
                return True
            if _check_gradlew(chunk, tokens, None):
                return True
            if _check_sql(chunk, tokens, None):
                return True
        return False
    except Exception:
        return True
