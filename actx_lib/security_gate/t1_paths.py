"""actx security gate - T1: sensitive file & credential access (TK-59 split).

Body unchanged from the pre-split monolith - see tools/ast_identity_check.py.
"""

import fnmatch
import functools
import os
import posixpath
import re
import shlex

from .common import (
    SecurityDecision,
    _matches_new_secret_substrings,
    _quick_check_hit,
    _strip_actx_prefix,
    _strip_redirection,
    _unwrap_tokens,
    _RE_EXFIL_VARS,
    _RE_SENSITIVE_QUICK_CHECK,
)


# ----------------------------------------------------------------------
# T1: Protected sensitive paths and tokens
# ----------------------------------------------------------------------

_PROTECTED_BASENAMES = {
    ".env",
    "id_rsa",
    "id_ed25519",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519_sk",
    "id_ecdsa_sk",
    "known_hosts",
    "authorized_keys",
    "credentials",
    ".netrc",
    "shadow",
    "gshadow",
    "sudoers",
    "master.passwd",
    ".npmrc",
    ".pypirc",
    ".git-credentials",
    "privkey.pem",
    "server.key",
    "service_account.json",
    # --- TK-57 S1 (STEP-01, REQ-01): secret-name class additions ---
    "kubeconfig",
    ".vault-token",
    ".boto",
    ".s3cfg",
    ".dockercfg",
    "secring.gpg",
    "wp-config.php",
}

_SECRET_EXTENSIONS = (
    ".pem",
    ".key",
    ".pkcs12",
    ".pfx",
    ".p12",
    ".kdbx",
    ".keystore",
    ".jks",
    # --- TK-57 S1 (STEP-01, REQ-01) ---
    ".p8",
    ".ppk",
    ".ovpn",
    ".keychain",
    ".keychain-db",
)

# TK-57 S1 (STEP-01, REQ-01): secret-name keyword class. Unlike the
# unconditional credentials/password/passwd substring check below, these
# are gated by the caller (_check_sensitive_paths) to only the two cases
# REQ-01 defines: (a) any path-like token (contains '/' or '.') on any
# head, or (b) a non-flag operand of a head whose arguments are file paths
# (_SECRET_KEYWORD_FILE_HEADS, or git's own read verbs) - a bare
# subcommand word like 'secrets' in `kubectl get secrets` or `gh secret
# list` is out of scope (that class is a different problem - TK-52).
_SECRET_KEYWORDS = (
    "secret",
    "apikey",
    "api_key",
    "api-key",
    "adminsdk",
    "service-account",
    "service_account",
)

# File-read heads whose non-flag operands are file paths: REQ-01 condition
# (b). grep/rg/egrep/fgrep already exclude their pattern argument via the
# existing exclusion logic below (git-grep gets the same treatment).
_SECRET_KEYWORD_FILE_HEADS = frozenset({
    "cat", "head", "tail", "less", "more", "wc", "sort", "uniq", "strings",
    "xxd", "od", "hexdump", "base64", "cp", "mv", "scp", "rsync", "tar",
    "zip", "diff", "cmp", "nl", "tac", "file", "stat",
    "grep", "rg", "egrep", "fgrep",
})

# git subcommands that read file/blob content - REQ-01's "git-чтение"
# class. `git grep`'s pattern argument is excluded the same way a bare
# grep's is (see _check_sensitive_paths).
_GIT_READ_VERBS = frozenset({
    "show", "diff", "log", "blame", "cat-file", "grep", "archive",
    "annotate", "difftool",
})

_ALLOWED_ENV_SUFFIXES = (
    ".example",
    ".sample",
    ".template",
    ".dist",
    ".test",
    ".testing",
    ".defaults",
    ".schema",
)

# Data-driven table of cloud/data CLI credential stores (T1). Three record kinds:
#   ("basename", name) -> exact basename match anywhere in the tree
#   ("glob", pattern)  -> fnmatch on the basename, anywhere
#   ("home", pattern)  -> path anchored at $HOME; '~' prefixes the template, tail
#                         '*' segments are fnmatch globs and a '/**' suffix
#                         protects everything inside that directory.
# Paths verified against upstream CLI docs/sources (WRANGLER, gcloud, Railway,
# Clerk, Vercel, Netlify, Supabase, flyctl, SnowSQL, psql, MySQL, Databricks).
# Adding a new protected path is a one-line data edit.
_PROTECTED_PATHS = (
    # --- data tool configs holding plaintext credentials ---
    ("basename", ".pgpass"),
    ("basename", ".my.cnf"),
    ("basename", ".databrickscfg"),
    ("basename", "key.properties"),
    # --- MCP / agent desktop configs holding API keys ---
    ("basename", ".mcp.json"),
    ("basename", "mcp.json"),
    ("basename", "claude_desktop_config.json"),
    # --- Claude Code / Claude Desktop MCP stores (TK-48) ---
    # ~/.claude.json: local- and user-scoped mcpServers + cached OAuth
    #   metadata (verified: code.claude.com/docs/en/mcp).
    # ~/.config/mcp/**: xdg variant for the proposed universal mcp.json
    #   standard (modelcontextprotocol discussion #2218 standardizes the
    #   filename; no ratified directory yet — defense-in-depth, near-zero
    #   false-positive surface).
    # ~/Library/Application Support/Claude/**: Claude Desktop data dir; the
    #   config at .../claude_desktop_config.json embeds server API keys
    #   (verified: modelcontextprotocol.io quickstart/user), the rest of the
    #   directory holds desktop app state — protected as a whole.
    ("home", "~/.claude.json"),
    ("home", "~/.config/mcp/**"),
    ("home", "~/Library/Application Support/Claude/**"),
    # --- Terraform state & variable files (secrets in plaintext) ---
    ("glob", "*.tfstate"),
    ("glob", "*.tfstate.*"),
    ("glob", "*.tfvars"),
    ("glob", "*.tfvars.json"),
    # --- Railway ---
    ("home", "~/.railway/config.json"),
    # --- Clerk ---
    ("home", "~/.config/clerk-cli/config.json"),
    ("home", "~/Library/Preferences/clerk-cli/config.json"),
    ("home", "~/.local/share/clerk-cli/credentials"),
    ("home", "~/Library/Application Support/clerk-cli/credentials"),
    # --- Netlify ---
    ("home", "~/.config/netlify/config.json"),
    ("home", "~/Library/Preferences/netlify/config.json"),
    ("home", "~/.netlify/config.yml"),
    # --- Fly.io ---
    ("home", "~/.fly/config.yml"),
    # --- Supabase ---
    ("home", "~/.supabase/access-token"),
    # --- Cloudflare Wrangler ---
    ("home", "~/.wrangler/config/default.*"),
    ("home", "~/Library/Preferences/.wrangler/config/default.*"),
    ("home", "~/.config/.wrangler/config/default.*"),
    # --- Google Cloud SDK ---
    ("home", "~/.config/gcloud/credentials*"),
    ("home", "~/.config/gcloud/legacy_credentials/**"),
    ("home", "~/.config/gcloud/access_tokens.db"),
    # --- Vercel ---
    ("home", "~/.vercel/auth.json"),
    # --- Snowflake SnowSQL ---
    ("home", "~/.snowsql/config"),
)

_PROTECTED_BASENAME_ENTRIES = tuple(e[1] for e in _PROTECTED_PATHS if e[0] == "basename")
_PROTECTED_GLOB_ENTRIES = tuple(e[1] for e in _PROTECTED_PATHS if e[0] == "glob")


@functools.lru_cache(maxsize=16)
def _protected_home_entries(home: str) -> tuple:
    """Expand home-anchored records for the given $HOME.

    Derived lazily (not at import) so a mutated HOME in long-lived test or
    agent processes is honored. Returns lowercase (abs_path, rel_path, deep)
    triples for case-insensitive comparison; rel_path equals abs_path when
    the template is not anchored under home.
    """
    entries = []
    for rec, deep in ((e[1], e[1].endswith("/**")) for e in _PROTECTED_PATHS if e[0] == "home"):
        template = rec[:-3] if deep else rec
        abs_p = os.path.expandvars(os.path.expanduser(template)).rstrip("/").lower()
        rel_p = abs_p[len(home) + 1:] if home and abs_p.startswith(home.lower() + "/") else abs_p
        entries.append((abs_p, rel_p, deep))
    return tuple(entries)
_RE_SUBSHELL_EXTRACT = re.compile(r"\$\(([^)]+)\)|`([^`]+)`|<\(([^)]+)\)|>\(([^)]+)\)")


def _matches_protected_paths(candidate: str) -> bool:
    """Match an expanded path candidate against the _PROTECTED_PATHS table."""
    candidate = candidate.lower()
    base = os.path.basename(candidate)
    if base in _PROTECTED_BASENAME_ENTRIES:
        return True
    if any(fnmatch.fnmatch(base, pattern) for pattern in _PROTECTED_GLOB_ENTRIES):
        return True
    entries = _protected_home_entries(os.path.expanduser("~"))
    for abs_p, rel_p, deep in entries:
        if deep:
            if candidate == abs_p or candidate == rel_p:
                return True
            if candidate.startswith(abs_p + "/") or candidate.startswith(rel_p + "/"):
                return True
        elif any(c in abs_p for c in "*?["):
            # Tail segments may carry globs (default.*, credentials*) —
            # match structurally against both the absolute and relative form.
            if fnmatch.fnmatch(candidate, abs_p) or fnmatch.fnmatch(candidate, rel_p):
                return True
        elif candidate == abs_p or candidate == rel_p:
            return True
        elif candidate.endswith("/" + abs_p) or candidate.endswith("/" + rel_p):
            # Relative candidates (e.g. git HEAD: notation stripped to a repo
            # path) match on the tail so home configs are caught at any depth.
            return True
    return False


def _is_sensitive_path(path: str, check_secret_keywords: bool = False) -> bool:
    """Check whether a normalized path points to a protected credential or secret file.

    check_secret_keywords (TK-57 S1, REQ-01): the caller has already
    confirmed this token satisfies condition (a) or (b) - see
    _SECRET_KEYWORDS above - and asks _is_sensitive_path to also match the
    'secret'/'apikey'/service-account keyword class. Defaults False so
    every other call site (network-exfiltration @file checks, recursive
    subshell checks) keeps its prior behavior unchanged.
    """
    if not path:
        return False

    # Super fast regex search (<0.0001ms), widened by the cheap substring
    # pre-filter above for the TK-57 S1 secret-name class records.
    if not _quick_check_hit(path):
        return False

    clean_path = _strip_redirection(path).strip("'\"")
    if not clean_path:
        return False

    # Handle git object notation HEAD:.env or master:config/.env
    if ":" in clean_path and not clean_path.startswith("http:") and not clean_path.startswith("https:"):
        clean_path = clean_path.split(":", 1)[1]

    # Normalize slashes and trailing dots/slashes
    norm_path = clean_path.replace("\\", "/").rstrip("/.")
    if not norm_path:
        return False

    # Resolve traversals
    try:
        norm_path = posixpath.normpath(norm_path)
    except Exception:
        pass

    basename = os.path.basename(norm_path)
    base_lower = basename.lower()

    # Exclude HTTP headers / auth tokens in requests (e.g. Authorization: Bearer ...)
    if (
        norm_path.startswith("authorization:")
        or norm_path.startswith("bearer ")
        or norm_path.startswith("basic ")
        or norm_path.startswith("x-api-key:")
        or norm_path.startswith("cookie:")
        or base_lower.startswith("authorization:")
        or base_lower.startswith("bearer ")
        or base_lower.startswith("x-api-key:")
    ):
        return False

    # Allowed .env templates (e.g. .env.example)
    if base_lower.startswith(".env.") and any(base_lower.endswith(sfx) for sfx in _ALLOWED_ENV_SUFFIXES):
        return False

    # Table-scoped template suffix exemption: terraform.tfvars.example and
    # similar glob-record template files are safe to read (basename records
    # intentionally keep denying: their template naming is not standardized).
    _, ext = posixpath.splitext(base_lower)
    if ext and any(base_lower.endswith(sfx) for sfx in _ALLOWED_ENV_SUFFIXES):
        stem = base_lower[: -len(ext)]
        if any(fnmatch.fnmatch(stem, pattern) for pattern in _PROTECTED_GLOB_ENTRIES):
            return False

    # Data-driven protected-path table (basename / glob / $HOME-anchored records)
    candidate = os.path.expandvars(os.path.expanduser(norm_path))
    if _matches_protected_paths(candidate):
        return True
    if base_lower == ".env" or base_lower.startswith(".env.") or base_lower.startswith(".envrc"):
        return True

    # State files containing auth / secrets (*state*.json, .codex-global-state*)
    if (
        base_lower.startswith(".codex-global-state")
        or base_lower == ".codex-global-state.json"
        or (base_lower.startswith(".state") and base_lower.endswith(".json"))
    ):
        return True

    # Auth stores and docker configs (e.g. auth.json, .docker/config.json)
    if base_lower == "auth.json" or ("config.json" in base_lower and any(k in norm_path for k in (".docker", ".aws", ".gcp", ".azure", ".gcloud", ".kube"))):
        return True

    # Exact protected basenames (e.g. shadow, sudoers, id_rsa, credentials, .netrc, etc.)
    if base_lower in _PROTECTED_BASENAMES or basename in _PROTECTED_BASENAMES:
        return True

    # Check glob variations of protected basenames (e.g. .[e]nv, .?nv, .e??, .en*, id_r*)
    if any(c in base_lower for c in ("*", "?", "[")):
        clean_glob_base = re.sub(r"\[(.)\]", r"\1", base_lower)
        clean_no_glob = re.sub(r"[*?]+", "", clean_glob_base)
        if clean_no_glob in _PROTECTED_BASENAMES:
            return True
        if re.match(r"^\.?e[n?*][v?*]", clean_glob_base):
            return True
    if base_lower.startswith(".env") or base_lower.startswith("id_"):
        return True

    # Secret file extensions (.pem, .key, .pfx, .pkcs12, .p12, .kdbx, .keystore)
    _, ext = posixpath.splitext(base_lower)
    if ext in _SECRET_EXTENSIONS:
        return True

    # Secret keywords in filename: credentials, password, passwd
    if "credentials" in base_lower or "password" in base_lower or "passwd" in base_lower:
        return True

    # TK-57 S1 (STEP-01, REQ-01): secret/apikey/service-account keyword
    # class - gated by the caller (see check_secret_keywords docstring
    # above), so a bare 'secrets' subcommand word (`kubectl get secrets`)
    # never reaches here unqualified.
    if check_secret_keywords and any(kw in base_lower for kw in _SECRET_KEYWORDS):
        return True

    # Token files (token, token.json, token.txt, auth_token, session_token, access_token, etc.)
    _TOKEN_BASENAMES = {
        "token", "tokens", ".token", ".tokens",
        "token.json", "token.txt", "tokens.json", "auth_token.json",
        "access_token.json", "token.yaml", "token.yml", "tokens.yaml", "tokens.yml",
        "auth_token", "access_token", "session_token", "bearer_token", "api_token",
        "gh_token", "github_token", "gitlab_token", "npm_token"
    }
    if base_lower in _TOKEN_BASENAMES or (base_lower.startswith(".") and base_lower[1:] in _TOKEN_BASENAMES):
        return True

    # SSH key globs / private keys
    if base_lower.startswith("id_rsa") or base_lower.startswith("id_ed25519") or base_lower.startswith("id_dsa") or base_lower.startswith("id_ecdsa"):
        return True

    # SSH credential directory
    if base_lower == ".ssh" or norm_path == ".ssh" or norm_path.startswith(".ssh/") or "/.ssh" in norm_path or norm_path.startswith("~/.ssh"):
        return True

    # Kubernetes config (holds cluster certificates and bearer tokens)
    if norm_path.endswith(".kube/config") or norm_path == ".kube/config" or norm_path.endswith("/.kube/config"):
        return True

    # System critical files
    if norm_path in (
        "/etc/shadow",
        "/etc/gshadow",
        "/etc/sudoers",
        "/etc/master.passwd",
        "/etc/security",
    ) or norm_path.startswith("/etc/sudoers.d"):
        return True

    return False


def _env_is_effective_head(raw_tokens: list[str]) -> bool:
    """True when `env` is the effective command head - directly or behind an
    actx prefix (`env ...`, `actx run env ...`)."""
    stripped = _strip_actx_prefix(raw_tokens)
    base = raw_tokens if stripped is None else stripped
    return bool(base) and os.path.basename(base[0]) == "env"


def _check_sensitive_paths(command: str, raw_tokens: list[str]) -> SecurityDecision | None:
    # 0. Check subshell command substitutions & process substitutions <(...) only if triggers present
    if "$" in command or "`" in command or "<(" in command or ">(" in command:
        subshell_matches = _RE_SUBSHELL_EXTRACT.findall(command)
        for match_tuple in subshell_matches:
            inner_cmd = (match_tuple[0] or match_tuple[1] or match_tuple[2] or match_tuple[3]).strip()
            if inner_cmd:
                try:
                    inner_tokens = shlex.split(inner_cmd, posix=True)
                    inner_dec = _check_sensitive_paths(inner_cmd, inner_tokens)
                    if inner_dec:
                        return inner_dec
                except ValueError:
                    pass

    tokens = _unwrap_tokens(raw_tokens)
    excluded_src = None

    # Special case: 'env' or assignments alone without a subsequent command.
    # Parity behind an actx prefix (TK-39): `actx run env` / `actx --raw run
    # env` must deny exactly like bare `env` - an empty remainder after the
    # full strip is decided on the original tokens, never silently allowed.
    if not tokens and _env_is_effective_head(raw_tokens):
        return SecurityDecision(
            decision="deny",
            reason="Dumping or setting process environment via 'env' without a command is prohibited",
            category="T1_CREDENTIAL_ACCESS",
        )

    if not tokens:
        return None

    head = os.path.basename(tokens[0])

    # Special case: echo and printf simply outputting string text without redirection
    if head in ("echo", "printf"):
        has_redirection = any(("<" in tok or ">" in tok) for tok in raw_tokens) or "<" in command or ">" in command
        if not has_redirection:
            # Check for credential environment variable leakage in echo/printf
            if _RE_EXFIL_VARS.search(command):
                return SecurityDecision(
                    decision="deny",
                    reason=f"Printing credential environment variables via '{head}' is prohibited",
                    category="T1_CREDENTIAL_ACCESS",
                )
            return None

    # Special case: shell wrappers (sh, bash, zsh, dash, ksh, fish) with -c, -lc, -ilc, -ec
    if head in ("sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh", "fish", "busybox") and len(tokens) >= 2:
        c_opt_idx = -1
        for i, t in enumerate(tokens[1:], 1):
            if t.startswith("-") and "c" in t:
                c_opt_idx = i
                break
        if c_opt_idx != -1:
            # Find the actual script argument after -c (skipping '--' if present)
            target_idx = c_opt_idx + 1
            while target_idx < len(tokens) and tokens[target_idx] == "--":
                target_idx += 1
            if target_idx < len(tokens):
                inner_cmd = tokens[target_idx]
                # Back-edge (TK-59 STEP-R2): local import avoids a t1_paths
                # <-> engine module cycle (engine imports _check_sensitive_
                # paths at module load time).
                from .engine import evaluate_security
                inner_dec = evaluate_security(inner_cmd)
                if inner_dec.decision != "allow":
                    return inner_dec

    # Special case: language runtime inline evaluation (-c, -e, -r, --eval)
    if (
        head.startswith("python")
        or head in ("node", "nodejs", "ruby", "perl", "php", "lua", "bun", "deno")
    ) and len(tokens) >= 2:
        eval_idx = -1
        for i, t in enumerate(tokens[1:], 1):
            if t in ("-c", "-e", "-r", "--eval") or (t.startswith("-c") and len(t) > 2):
                eval_idx = i
                break
        if eval_idx != -1:
            target_idx = eval_idx + 1
            if tokens[eval_idx].startswith("-c") and len(tokens[eval_idx]) > 2:
                script_body = tokens[eval_idx][2:]
            elif target_idx < len(tokens):
                script_body = tokens[target_idx]
            else:
                script_body = ""

            if script_body:
                # Check for sensitive path tokens or exfiltration in inline script
                for bad_token in (
                    ".env",
                    "id_rsa",
                    "id_ed25519",
                    "credentials",
                    "/etc/shadow",
                    "authorized_keys",
                    "known_hosts",
                    "/etc/sudoers",
                    ".codex-global-state",
                    ".netrc",
                    ".kube",
                ):
                    if bad_token in script_body:
                        return SecurityDecision(
                            decision="deny",
                            reason=f"Inline {head} script accesses sensitive path '{bad_token}'",
                            category="T1_CREDENTIAL_ACCESS",
                        )
                # Check for env dumping in inline script
                if any(dump in script_body for dump in ("os.environ", "process.env", "ENV.to_h", "ENV[")):
                    return SecurityDecision(
                        decision="deny",
                        reason=f"Inline {head} script dumps process environment secrets",
                        category="T1_CREDENTIAL_ACCESS",
                    )
                # Check for socket connections in inline script
                if any(net_mod in script_body for net_mod in ("socket", "net.connect", "TCPSocket", "fsockopen", "urllib.request", "requests")):
                    return SecurityDecision(
                        decision="deny",
                        reason=f"Inline {head} script establishes network connections",
                        category="T3_OBFUSCATION_EVAL",
                    )

    # Special case: environment variable dumping (printenv, env)
    if head == "printenv" and (not tokens[1:] or any(tok.startswith("-") for tok in tokens[1:])):
        return SecurityDecision(
            decision="deny",
            reason="Dumping entire process environment is prohibited (credential leakage)",
            category="T1_CREDENTIAL_ACCESS",
        )
    if head == "env" and not tokens[1:]:
        return SecurityDecision(
            decision="deny",
            reason="Dumping entire process environment is prohibited (credential leakage)",
            category="T1_CREDENTIAL_ACCESS",
        )

    # Special case: macOS Keychain dump
    if head == "security":
        subcmds = {
            "dump-keychain",
            "find-generic-password",
            "find-internet-password",
            "find-certificate",
            "find-key",
            "export",
        }
        if any(tok in subcmds for tok in tokens[1:]):
            return SecurityDecision(
                decision="deny",
                reason="Direct access to macOS Keychain secrets is prohibited",
                category="T1_CREDENTIAL_ACCESS",
            )

    # Special case: safe template copying (cp .env.example .env) -> allowed if destination is also .env
    if head == "cp" and len(tokens) >= 3:
        src = _strip_redirection(tokens[1]).strip("'\"")
        src_base = os.path.basename(src.replace("\\", "/"))
        dst = _strip_redirection(tokens[2]).strip("'\"")
        dst_base = os.path.basename(dst.replace("\\", "/"))
        if src_base.startswith(".env.") and any(src_base.endswith(sfx) for sfx in _ALLOWED_ENV_SUFFIXES):
            if dst_base == ".env" or dst_base.startswith(".env.") or dst_base.startswith(".envrc"):
                return None

    # Exclusions for safe developer tools (git commit messages, branch/tag names, grep regex patterns, pytest filter)
    excluded_tokens = set()
    if head == "git" and len(tokens) >= 2:
        for idx, tok in enumerate(tokens[1:], 1):
            if tok in ("-m", "--message") and idx + 1 < len(tokens):
                excluded_tokens.add(tokens[idx + 1])
            elif tok.startswith("--message=") or tok.startswith("-m="):
                excluded_tokens.add(tok)
            if tokens[1] in ("branch", "tag", "checkout", "switch") and tok not in ("branch", "tag", "checkout", "switch") and not tok.startswith("-"):
                excluded_tokens.add(tok)

    # TK-57 S1 (REQ-01): `git grep`'s pattern argument is excluded the same
    # way a bare grep's is (offset by the extra 'git'+'grep' tokens).
    if head == "git" and len(tokens) >= 3 and tokens[1] == "grep":
        has_f = any(t in ("-f", "--file") or (t.startswith("-f") and len(t) > 2) or t.startswith("--file=") for t in tokens[2:])
        for idx, tok in enumerate(tokens[2:], 2):
            if tok in ("-e", "--regexp") and idx + 1 < len(tokens):
                excluded_tokens.add(tokens[idx + 1])
            elif tok.startswith("--regexp=") or (tok.startswith("-e") and len(tok) > 2):
                excluded_tokens.add(tok)
        if not excluded_tokens and not has_f:
            positional = [t for t in tokens[2:] if not t.startswith("-")]
            if positional:
                excluded_tokens.add(positional[0])

    if head in ("grep", "rg", "ag", "ack") and len(tokens) >= 2:
        has_f = any(t in ("-f", "--file") or (t.startswith("-f") and len(t) > 2) or t.startswith("--file=") for t in tokens[1:])
        # Check if -e or --regexp was used
        for idx, tok in enumerate(tokens[1:], 1):
            if tok in ("-e", "--regexp") and idx + 1 < len(tokens):
                excluded_tokens.add(tokens[idx + 1])
            elif tok.startswith("--regexp=") or (tok.startswith("-e") and len(tok) > 2):
                excluded_tokens.add(tok)
        if not excluded_tokens and not has_f:
            # First positional arg is search pattern
            positional = [t for t in tokens[1:] if not t.startswith("-")]
            if positional:
                excluded_tokens.add(positional[0])

    if head == "pytest" and len(tokens) >= 2:
        for idx, tok in enumerate(tokens[1:], 1):
            if tok in ("-k", "-m") and idx + 1 < len(tokens):
                excluded_tokens.add(tokens[idx + 1])

    if not _quick_check_hit(command):
        return None

    # TK-57 S1 (REQ-01) condition (b): non-flag operands of file-read heads
    # and git's own read verbs are in scope for the secret-keyword class
    # even when the operand itself isn't path-like (bare `cat api_key`).
    secret_keyword_head = head in _SECRET_KEYWORD_FILE_HEADS or (
        head == "git" and len(tokens) >= 2 and tokens[1] in _GIT_READ_VERBS
    )
    # Perf: a new-record substring can only appear in a token if it also
    # appears somewhere in the full command (tokens are substrings of it) -
    # so the extra per-token substring scan only runs when this one,
    # command-wide check already found a hit. Keeps the common case (no
    # secret-name hint anywhere) at the original per-token regex-only cost
    # (test_perf.py's 150-file wide command).
    command_has_new_secret_hint = _matches_new_secret_substrings(command)

    # Generic file reader / flag / argument / shell redirection inspection
    for idx, tok in enumerate(tokens):
        if tok in excluded_tokens or tok == excluded_src:
            continue
        clean = _strip_redirection(tok).strip("'\"")
        if not clean:
            continue
        if tok.startswith("--grep=") or tok.startswith("-G") or tok.startswith("-S"):
            continue
        if not _RE_SENSITIVE_QUICK_CHECK.search(clean) and not (
            command_has_new_secret_hint and _matches_new_secret_substrings(clean)
        ):
            continue
        # TK-57 S1 (REQ-01) condition (a): any path-like token (contains
        # '/' or '.') is in scope for the secret-keyword class regardless
        # of head; condition (b) additionally covers non-flag, non-head
        # operands of the file-read heads / git-read verbs above.
        check_kw = ("/" in clean or "." in clean) or (
            secret_keyword_head and idx != 0 and not clean.startswith("-")
        )
        if _is_sensitive_path(clean, check_secret_keywords=check_kw):
            return SecurityDecision(
                decision="deny",
                reason=f"Access to sensitive credential/file '{clean}' is prohibited",
                category="T1_CREDENTIAL_ACCESS",
            )
        if "=" in clean and not clean.startswith("--message="):
            val = clean.split("=", 1)[1].strip("'\"")
            val_kw = ("/" in val or "." in val) or secret_keyword_head
            if _is_sensitive_path(val, check_secret_keywords=val_kw):
                return SecurityDecision(
                    decision="deny",
                    reason=f"Access to sensitive credential/file '{val}' is prohibited",
                    category="T1_CREDENTIAL_ACCESS",
                )
        if clean.startswith("-f") and len(clean) > 2 and not clean.startswith("--"):
            val = clean[2:].strip("'\"")
            val_kw = ("/" in val or "." in val) or secret_keyword_head
            if _is_sensitive_path(val, check_secret_keywords=val_kw):
                return SecurityDecision(
                    decision="deny",
                    reason=f"Access to sensitive credential/file '{val}' is prohibited",
                    category="T1_CREDENTIAL_ACCESS",
                )

    return None
