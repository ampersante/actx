"""actx security gate - shared primitives (TK-59 package split).

SecurityDecision result type, the allow sentinel, the argv-unwrapping
helpers used by every T-level check module (actx-prefix / wrapper-command /
run-prefix stripping), and the regexes + tables shared by two or more
T-level modules. Bodies below are unchanged from the pre-split monolith
(``git show 4383931:actx_lib/security_gate.py``) - see
tools/ast_identity_check.py.
"""

from collections import namedtuple
import os
import re

from actx_lib import cli_families


SecurityDecision = namedtuple("SecurityDecision", ["decision", "reason", "category"])

_DECISION_ALLOW = SecurityDecision(decision="allow", reason=None, category=None)

_WRAPPER_COMMANDS = {
    "env",
    "command",
    "builtin",
    "noglob",
    "exec",
    "nohup",
    "nice",
    "time",
    "timeout",
    "stdbuf",
    "ionice",
    "xargs",
    "parallel",
    "systemd-run",
}

# Pre-compiled fast regexes
_RE_STRIP_REDIRECTION = re.compile(r"^[0-9]*[<>]>?&?|[&;]+$")
_RE_PIPE_TO_SHELL = re.compile(
    r"\|\s*(env(\s+-[a-zA-Z]+|\s+[a-zA-Z_0-9]+=[\S]+)*\s+|command\s+|sudo\s+|/bin/|/usr/bin/|/usr/local/bin/|\S+/)?(sh|bash|zsh|dash|ksh|csh|tcsh|fish|python|python3|python\d+\.\d+|perl|ruby|node|nodejs|bun|deno|php|lua|tclsh|Rscript)(\s|$)",
    re.IGNORECASE,
)
_RE_FORK_BOMB = re.compile(r"([:a-zA-Z0-9_]+)\s*\(\s*\)\s*\{\s*\1\s*\|\s*\1\s*&\s*\}\s*;\s*\1")
_RE_EXFIL_VARS = re.compile(
    r"\$\{?(?:[A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASS|PASSWORD|AUTH|CREDENTIAL|OPENAI|ANTHROPIC|AWS|GITHUB|DATABASE_URL|STRIPE)[A-Z0-9_]*)\}?",
    re.IGNORECASE,
)
_RE_SENSITIVE_QUICK_CHECK = re.compile(
    r"(?:\.env|\benv\b|\.e[\w?*]{2}|\.ssh|id_|credentials|shadow|gshadow|sudoers|passwd|password|token|key|cert|\.pem|\.pfx|\.p12|\.pkcs12|\.kdbx|\.netrc|\.npmrc|\.pypirc|\.codex-global-state|\.kube|~|\$|/etc|\[[a-z0-9]\]"
    r"|pgpass|my\.cnf|snowsql|databrickscfg|mcp\.json|key\.properties|wrangler|gcloud|vercel|netlify|supabase|flyctl|\.fly|railway|clerk|tfstate|tfvars|auth\.json|claude_desktop_config"
    # TK-48: without these the home records above are dead code — the absolute
    # forms below match no other alternative, and _is_sensitive_path early-
    # returns on a failed quick check before consulting _PROTECTED_PATHS.
    r"|claude\.json|config/mcp|application[ /]support/claude)",
    re.IGNORECASE,
)

# TK-57 S1 (STEP-01, REQ-01/A1): quick-check reachability for the new
# secret-name records ('key' already covers apikey/api_key/.keychain*,
# 'token' already covers .vault-token - confirmed by pin, not by this
# comment). A plain substring scan, not folded into the regex above: that
# regex is the hottest path in the gate (every token of every command),
# and benchmarking showed adding these ~12-16 alternatives there costs
# ~20-30% extra time on a wide multi-file command (test_perf.py's 150-file
# case) vs ~7-8% for a separate short-circuited substring pass (TK-57
# session evidence). This is a coarse, permissive pre-filter like the
# regex above - it may over-match; precision is enforced later (the
# basename/extension tables, and check_secret_keywords gating in
# _is_sensitive_path for the broad keyword class).
_NEW_SECRET_QUICK_CHECK_SUBSTRINGS = (
    ".p8", "ppk", "ovpn", "boto", "s3cfg", "dockercfg", "kubeconfig",
    "secring", "wp-config",
    "secret", "apikey", "api_key", "api-key", "adminsdk",
    "service-account", "service_account",
)


def _matches_new_secret_substrings(text: str) -> bool:
    low = text.lower()
    return any(kw in low for kw in _NEW_SECRET_QUICK_CHECK_SUBSTRINGS)


def _quick_check_hit(text: str) -> bool:
    return bool(_RE_SENSITIVE_QUICK_CHECK.search(text)) or _matches_new_secret_substrings(text)


def _strip_redirection(token: str) -> str:
    """Strip leading/trailing shell redirection and background symbols."""
    clean = _RE_STRIP_REDIRECTION.sub("", token)
    return clean.strip("&; \t")


def _strip_actx_prefix(tokens: list[str]) -> list[str] | None:
    """Slice a leading ``actx`` invocation off an exec-array.

    Form (data in cli_families, mirroring cli.py): ``actx [global flags]
    [run [leading run flags]] ...``. The skip lists are closed literal sets -
    no generic ``startswith("-")``. ``actx rewrite`` / ``actx hook`` take a
    command string / stdin, not an argv, so their literals are absent from
    the skip lists and unwrapping stops at them (their argument is never
    treated as an executable command). Returns the remaining tokens (possibly
    empty) or None when the array is not actx-prefixed.
    """
    if not tokens or os.path.basename(tokens[0]) != "actx":
        return None
    idx = 1
    n = len(tokens)
    while idx < n and tokens[idx] in cli_families.ACTX_GLOBAL_FLAGS:
        idx += 1
    if idx < n and tokens[idx] == cli_families.ACTX_RUN_LITERAL:
        idx += 1
        while idx < n and tokens[idx] in cli_families.ACTX_RUN_FLAGS:
            idx += 1
    return tokens[idx:]


def _unwrap_tokens(tokens: list[str]) -> list[str]:
    """Strip actx invocations, wrapper commands and env assignments."""
    stripped = _strip_actx_prefix(tokens)
    if stripped is not None:
        tokens = stripped
    # TK-55 (F4): run-prefixes (`uv run <argv>`, `xcrun [flags] simctl
    # <argv>`) hide the effective head from every consumer of this helper,
    # so they are unwrapped inside the same loop - wrapper chains then
    # work in any order (`nice uv run rm`, `uv run env rm`). Unlike
    # _WRAPPER_COMMANDS tokens (dropped), consumed run-prefix tokens are
    # kept and appended at the end: file-valued flags (`uv run --env-file
    # .env`) must stay visible to the token-level scans (T1).
    # cli_families.run_prefix_split fails open (None) on unknown flags or
    # a missing inner command, and each split strictly shortens the
    # scanned list, so the loop terminates.
    consumed_prefix: list[str] = []
    idx = 0
    while True:
        while idx < len(tokens):
            tok = tokens[idx]
            base = os.path.basename(tok)
            if base in _WRAPPER_COMMANDS:
                idx += 1
                while idx < len(tokens) and (
                    tokens[idx].startswith("-")
                    or "=" in tokens[idx]
                    or tokens[idx].isdigit()
                    or bool(re.match(r"^\d+[smhd]?$", tokens[idx]))
                ):
                    idx += 1
                continue
            if "=" in tok and not tok.startswith("-"):
                idx += 1
                continue
            break
        rest = tokens[idx:] if idx < len(tokens) else []
        split = cli_families.run_prefix_split(rest)
        if split is None:
            return rest + consumed_prefix
        inner_argv, consumed = split
        consumed_prefix += consumed
        tokens = inner_argv
        idx = 0
