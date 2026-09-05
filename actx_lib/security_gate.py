"""Deterministic, stdlib-only L7 Security Gatekeeper for actx hook.

Protects agentic coding sessions (Claude Code, Codex CLI) against:
- T1: Sensitive file & credential access (local exfiltration)
- T2: Out-of-band network exfiltration
- T3: Shell obfuscation, dynamic eval & remote pipeline execution
- T4: Destructive OS mutations & persistence hijacking
- T5: Supply chain & insecure package lifecycle installations
- T6: High-risk git/cargo/cloud-infra mutations requiring human confirmation ("ask")
- T7: Action space backstop & prohibited file operations (§26a core-rules)

Zero external dependencies (Python 3.14 stdlib only).
Evaluation latency strictly < 1.0 ms wall time.
"""

from collections import namedtuple
import fnmatch
import functools
import os
import posixpath
import re
import shlex

from actx_lib import cli_families

SecurityDecision = namedtuple("SecurityDecision", ["decision", "reason", "category"])

_DECISION_ALLOW = SecurityDecision(decision="allow", reason=None, category=None)

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
)

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

_NETWORK_CLIENTS = {
    "curl",
    "wget",
    "http",
    "nc",
    "netcat",
    "ncat",
    "socat",
    "telnet",
    "ftp",
    "sftp",
    "whois",
}

_DNS_TOOLS = {
    "dig",
    "nslookup",
    "host",
}

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
_RE_PROCESS_SUBST = re.compile(
    r"(?:sh|bash|zsh|dash|ksh|source|\.|\btemp\b|\btee\b)\s+(?:-[a-zA-Z0-9_\-]+\s+)*(?:<\s*)?[<>]?\(\s*(?:curl|wget|fetch|base64|xxd|echo|printf|cat|head|tail|gzip|gunzip|tar|openssl)",
    re.IGNORECASE,
)
_RE_FORK_BOMB = re.compile(r"([:a-zA-Z0-9_]+)\s*\(\s*\)\s*\{\s*\1\s*\|\s*\1\s*&\s*\}\s*;\s*\1")
_RE_INLINE_SOCKET = re.compile(
    r"(python|python3|perl|ruby|node|nodejs|php)\s+.*(-c|-e|-r|--eval)\s+.*(socket|subprocess\.Popen|pty\.spawn|connect\(|fsockopen)",
    re.IGNORECASE | re.DOTALL,
)
_RE_SUBSHELL_EXTRACT = re.compile(r"\$\(([^)]+)\)|`([^`]+)`|<\(([^)]+)\)|>\(([^)]+)\)")
_RE_CHUNK_SPLIT = re.compile(r";|&&|\|\||\||&|\r?\n")
_RE_NORM_ATTACHED_REDIR = re.compile(r"(?<![0-9])([<>])")
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
    idx = 0
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
    return tokens[idx:] if idx < len(tokens) else []


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


def _is_sensitive_path(path: str) -> bool:
    """Check whether a normalized path points to a protected credential or secret file."""
    if not path:
        return False

    # Super fast regex search (<0.0001ms)
    if not _RE_SENSITIVE_QUICK_CHECK.search(path):
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

    if not _RE_SENSITIVE_QUICK_CHECK.search(command):
        return None

    # Generic file reader / flag / argument / shell redirection inspection
    for tok in tokens:
        if tok in excluded_tokens or tok == excluded_src:
            continue
        clean = _strip_redirection(tok).strip("'\"")
        if not clean:
            continue
        if tok.startswith("--grep=") or tok.startswith("-G") or tok.startswith("-S"):
            continue
        if not _RE_SENSITIVE_QUICK_CHECK.search(clean):
            continue
        if _is_sensitive_path(clean):
            return SecurityDecision(
                decision="deny",
                reason=f"Access to sensitive credential/file '{clean}' is prohibited",
                category="T1_CREDENTIAL_ACCESS",
            )
        if "=" in clean and not clean.startswith("--message="):
            val = clean.split("=", 1)[1].strip("'\"")
            if _is_sensitive_path(val):
                return SecurityDecision(
                    decision="deny",
                    reason=f"Access to sensitive credential/file '{val}' is prohibited",
                    category="T1_CREDENTIAL_ACCESS",
                )
        if clean.startswith("-f") and len(clean) > 2 and not clean.startswith("--"):
            val = clean[2:].strip("'\"")
            if _is_sensitive_path(val):
                return SecurityDecision(
                    decision="deny",
                    reason=f"Access to sensitive credential/file '{val}' is prohibited",
                    category="T1_CREDENTIAL_ACCESS",
                )

    return None


# ----------------------------------------------------------------------
# T2: Network Exfiltration
# ----------------------------------------------------------------------

def _check_exfiltration(command: str, raw_tokens: list[str]) -> SecurityDecision | None:
    # Raw socket exfiltration
    if "/dev/tcp/" in command or "/dev/udp/" in command:
        return SecurityDecision(
            decision="deny",
            reason="Direct raw socket access (/dev/tcp or /dev/udp) is prohibited",
            category="T2_NETWORK_EXFILTRATION",
        )

    tokens = _unwrap_tokens(raw_tokens)
    if not tokens:
        return None

    head = os.path.basename(tokens[0])
    if head in _NETWORK_CLIENTS or head in _DNS_TOOLS or head in ("ping", "traceroute"):
        # Check for subshell command substitutions inside network commands
        if "$(" in command or "`" in command:
            return SecurityDecision(
                decision="deny",
                reason=f"Command substitution in network client '{head}' is prohibited (potential exfiltration)",
                category="T2_NETWORK_EXFILTRATION",
            )

        # Check for credential environment variable names in URLs/arguments
        # Allow standard Authorization: Bearer $TOKEN in headers against HTTPS endpoints
        if "$" in command and _RE_EXFIL_VARS.search(command):
            is_legit_auth_header = (
                ("Authorization:" in command or "x-api-key:" in command or "--header=" in command or "-H " in command)
                and "https://" in command
            )
            if not is_legit_auth_header:
                return SecurityDecision(
                    decision="deny",
                    reason=f"Exfiltrating credential environment variables via network client '{head}' is prohibited",
                    category="T2_NETWORK_EXFILTRATION",
                )

        # Check for post file containing sensitive data: curl -d @.env, --data=@.env, -F file=@.env, etc.
        for tok in tokens[1:]:
            if "@" in tok:
                at_part = tok.split("@", 1)[1].split(";")[0].strip("'\"")
                if _is_sensitive_path(at_part):
                    return SecurityDecision(
                        decision="deny",
                        reason=f"Exfiltrating sensitive file '{at_part}' via network client '{head}' is prohibited",
                        category="T2_NETWORK_EXFILTRATION",
                    )
            if "--post-file=" in tok or tok == "--post-file":
                path_part = tok.split("--post-file=", 1)[1].strip("'\"") if "=" in tok else ""
                if _is_sensitive_path(path_part):
                    return SecurityDecision(
                        decision="deny",
                        reason="Exfiltrating sensitive file via wget is prohibited",
                        category="T2_NETWORK_EXFILTRATION",
                    )

        # Netcat/socat opening raw socket connections
        if head in ("nc", "netcat", "ncat", "socat", "telnet"):
            return SecurityDecision(
                decision="deny",
                reason=f"Spawning raw network connection via '{head}' is prohibited",
                category="T2_NETWORK_EXFILTRATION",
            )

    return None


# ----------------------------------------------------------------------
# T3: Shell Obfuscation, Dynamic Eval & Remote Pipelines
# ----------------------------------------------------------------------

def _check_obfuscation_and_eval(command: str, raw_tokens: list[str]) -> SecurityDecision | None:
    # 1. Pipe to shell interpreter: | sh, | bash, | /bin/bash, | env bash, | node
    if "|" in command:
        if _RE_PIPE_TO_SHELL.search(command):
            first_part = command.split("|", 1)[0].strip()
            try:
                first_tokens = shlex.split(first_part, posix=True) if first_part else []
            except ValueError:
                first_tokens = first_part.split()
            first_unwrapped = _unwrap_tokens(first_tokens)
            head = os.path.basename(first_unwrapped[0]) if first_unwrapped else ""
            if head in (
                "curl",
                "wget",
                "fetch",
                "base64",
                "xxd",
                "openssl",
                "echo",
                "printf",
                "cat",
                "head",
                "tail",
                "gzip",
                "gunzip",
                "tar",
                "uudecode",
                "rev",
                "sed",
                "awk",
            ):
                return SecurityDecision(
                    decision="deny",
                    reason="Piping payload directly to an interpreter is prohibited",
                    category="T3_OBFUSCATION_EVAL",
                )

    # 2. Process substitution into shell: bash <(curl ...), sh < <(wget ...)
    if "<(" in command or ">(" in command:
        if _RE_PROCESS_SUBST.search(command):
            return SecurityDecision(
                decision="deny",
                reason="Executing remote or encoded payload via process substitution <(...) is prohibited",
                category="T3_OBFUSCATION_EVAL",
            )

    # 3. Dynamic eval / exec: only when eval/exec is the primary command head (not docker exec, kubectl exec, find -exec)
    tokens = _unwrap_tokens(raw_tokens)
    if tokens:
        head = os.path.basename(tokens[0])
        if head == "eval" and len(tokens) >= 2:
            return SecurityDecision(
                decision="deny",
                reason="Dynamic shell evaluation via 'eval' is prohibited",
                category="T3_OBFUSCATION_EVAL",
            )
        if head == "builtin" and len(tokens) >= 2 and tokens[1] == "eval":
            return SecurityDecision(
                decision="deny",
                reason="Dynamic shell evaluation via 'builtin eval' is prohibited",
                category="T3_OBFUSCATION_EVAL",
            )
        if head == "exec" and len(tokens) >= 2 and not any(t.startswith("-") for t in tokens[1:]):
            if any(t.startswith("$") or t.startswith("`") or t.startswith("<(") or t.startswith("\"$") or t.startswith("'$") for t in tokens[1:]):
                return SecurityDecision(
                    decision="deny",
                    reason="Dynamic process execution via 'exec' with payload is prohibited",
                    category="T3_OBFUSCATION_EVAL",
                )

    # 4. Inline runtime socket connection
    if ("-c" in command or "-e" in command or "--eval" in command or "-r" in command) and _RE_INLINE_SOCKET.search(command):
        return SecurityDecision(
            decision="deny",
            reason="Inline script establishes raw network socket connection",
            category="T3_OBFUSCATION_EVAL",
        )

    return None


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
# T5: Supply Chain & Package Lifecycle Security
# ----------------------------------------------------------------------

def _check_supply_chain(command: str, raw_tokens: list[str]) -> SecurityDecision | None:
    """T5 supply-chain gate.

    Denies installs configured against unencrypted HTTP/git indexes.
    Asks (human confirmation) for auto-confirmed one-shot package execution:
    `npx -y/--yes <pkg>`, `pnpm dlx <pkg>`, `yarn dlx <pkg>` — these fetch and
    run an arbitrary package with no prompt, the exact supply-chain footgun
    T5 exists for.

    Bare `npx <tool>` WITHOUT -y/--yes is intentionally NOT asked: when the
    package is not installed, npx stops at an interactive install prompt;
    a stalled child is caught by the default hang-policy timeout instead.
    """
    if "=" not in command and not any(h in command for h in ("pip", "uv", "npm", "pnpm", "yarn", "python", "npx")):
        return None

    # Check for prefix environment variable registry overrides (PIP_INDEX_URL=http://, NPM_CONFIG_REGISTRY=http://)
    if "=" in command:
        for raw_tok in raw_tokens:
            if "=" in raw_tok and not raw_tok.startswith("-"):
                var_name, val = raw_tok.split("=", 1)
                var_upper = var_name.upper()
                if any(pkg_var in var_upper for pkg_var in ("PIP_INDEX", "PIP_EXTRA", "NPM_CONFIG_REGISTRY", "YARN_REGISTRY")):
                    val_lower = val.lower()
                    if val_lower.startswith("http://") or val_lower.startswith("git://") or val_lower.startswith("git+http://"):
                        return SecurityDecision(
                            decision="deny",
                            reason="Configuring unencrypted package index via environment variable is prohibited",
                            category="T5_SUPPLY_CHAIN",
                        )

    tokens = _unwrap_tokens(raw_tokens)
    if not tokens:
        return None

    head = os.path.basename(tokens[0])

    # Auto-confirmed one-shot package execution (TK-48, ask-tier): npx with
    # -y/--yes skips the install prompt; pnpm/yarn `dlx` is prompt-free by
    # design. Escalate to "ask" — see the function docstring for the bare
    # `npx <tool>` counterpart (allow path, hang-policy timeout).
    if head == "npx" and any(tok in ("-y", "--yes") for tok in tokens[1:]):
        return SecurityDecision(
            decision="ask",
            reason="npx -y/--yes auto-installs and executes an arbitrary npm package, requiring human confirmation",
            category="T5_SUPPLY_CHAIN",
        )
    if head in ("pnpm", "yarn") and "dlx" in tokens[1:]:
        return SecurityDecision(
            decision="ask",
            reason=f"{head} dlx auto-installs and executes an arbitrary package, requiring human confirmation",
            category="T5_SUPPLY_CHAIN",
        )

    # Insecure pip / uv install over plain HTTP or unencrypted git
    is_pip = (
        head in ("pip", "pip3")
        or head.startswith("python")
        or head == "uv"
    )
    if is_pip:
        if "install" in tokens or "add" in tokens or "ci" in tokens:
            for tok in tokens:
                tok_lower = tok.lower()
                if (
                    tok_lower.startswith("http://")
                    or tok_lower.startswith("git+http://")
                    or tok_lower.startswith("git://")
                    or tok_lower.startswith("git+git://")
                ):
                    return SecurityDecision(
                        decision="deny",
                        reason="Installing packages from unencrypted HTTP/git endpoints is prohibited",
                        category="T5_SUPPLY_CHAIN",
                    )
                if (
                    tok_lower.startswith("--extra-index-url=http://")
                    or tok_lower.startswith("--index-url=http://")
                    or tok_lower.startswith("--default-index=http://")
                    or tok_lower.startswith("--index=http://")
                    or tok_lower.startswith("-i=http://")
                    or tok_lower.startswith("--find-links=http://")
                    or tok_lower.startswith("-f=http://")
                ):
                    return SecurityDecision(
                        decision="deny",
                        reason="Configuring unencrypted HTTP package index is prohibited",
                        category="T5_SUPPLY_CHAIN",
                    )
            for idx, tok in enumerate(tokens):
                if tok in ("--extra-index-url", "--index-url", "--default-index", "--index", "-i", "--find-links", "-f") and idx + 1 < len(tokens):
                    if tokens[idx + 1].lower().startswith("http://") or tokens[idx + 1].lower().startswith("git://"):
                        return SecurityDecision(
                            decision="deny",
                            reason="Configuring unencrypted HTTP package index is prohibited",
                            category="T5_SUPPLY_CHAIN",
                        )

    # Insecure npm/pnpm/yarn install over plain HTTP or unencrypted git
    if head in ("npm", "pnpm", "yarn"):
        if "install" in tokens or "add" in tokens or "i" in tokens or "ci" in tokens or "update" in tokens or head == "yarn":
            for tok in tokens:
                tok_lower = tok.lower()
                if (
                    tok_lower.startswith("http://")
                    or tok_lower.startswith("git+http://")
                    or tok_lower.startswith("git://")
                    or "@http://" in tok_lower
                    or "@git://" in tok_lower
                ):
                    return SecurityDecision(
                        decision="deny",
                        reason="Installing packages from unencrypted HTTP/git endpoints is prohibited",
                        category="T5_SUPPLY_CHAIN",
                    )
                if tok_lower.startswith("--registry=http://") or tok_lower.startswith("-registry=http://"):
                    return SecurityDecision(
                        decision="deny",
                        reason="Configuring unencrypted HTTP package registry is prohibited",
                        category="T5_SUPPLY_CHAIN",
                    )
            for idx, tok in enumerate(tokens):
                if tok in ("--registry", "-registry") and idx + 1 < len(tokens):
                    if tokens[idx + 1].lower().startswith("http://") or tokens[idx + 1].lower().startswith("git://"):
                        return SecurityDecision(
                            decision="deny",
                            reason="Configuring unencrypted HTTP package registry is prohibited",
                            category="T5_SUPPLY_CHAIN",
                        )

    return None


# ----------------------------------------------------------------------
# T6: High-Risk Git Mutations (Ask Confirmation)
# ----------------------------------------------------------------------

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
    # Check for git -c alias definitions with destructive operations
    for idx_c, tok_c in enumerate(tokens):
        if tok_c.startswith("-c") or (tok_c == "-c" and idx_c + 1 < len(tokens)):
            val_c = tok_c.split("=", 1)[1] if "=" in tok_c else (tokens[idx_c + 1] if idx_c + 1 < len(tokens) else "")
            if ("alias." in val_c or "alias " in val_c) and ("force" in val_c or "reset" in val_c or "clean" in val_c or "+" in val_c):
                return SecurityDecision(
                    decision="ask",
                    reason="Executing high-risk git alias command requires human confirmation",
                    category="T6_HIGH_RISK_GIT",
                )

    if subcmd is None or subcmd_idx == -1:
        return None

    sub_args = tokens[subcmd_idx + 1 :]

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
    if subcmd == "install":
        # Check only before passthrough '--'
        cargo_args = sub_args[: sub_args.index("--")] if "--" in sub_args else sub_args
        if any(tok in ("-f", "--force") or tok.startswith("--force=") for tok in cargo_args):
            return SecurityDecision(
                decision="ask",
                reason="Executing cargo install --force overwrites binaries, requiring human confirmation",
                category="T6_HIGH_RISK_CARGO",
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
# flyctl is new. Non-cloud entries stay verbatim below.
_T6_NON_CLOUD_ASK_TABLE: dict[str, tuple[tuple[str, ...], ...]] = {
    "kubectl": (("delete",), ("scale",), ("rollout", "undo"), ("apply",)),
    "helm": (("uninstall",), ("rollback",)),
    "docker": (("system", "prune"), ("rm",), ("rmi",), ("compose", "down")),
    "simctl": (("erase",), ("delete",)),
    "flutter": (("clean",),),
    "xcodebuild": (("clean",),),
    "pod": (("deintegrate",),),
    "terraform": (("apply",), ("destroy",)),
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


# ----------------------------------------------------------------------
# T7: Action Space Backstop (§26a core-rules)
# ----------------------------------------------------------------------

_SOURCE_EXTENSIONS = {
    ".py",
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".json",
    ".md",
    ".toml",
    ".yaml",
    ".yml",
    ".sh",
    ".rs",
    ".go",
    ".html",
    ".css",
    ".c",
    ".cpp",
    ".h",
    ".hpp",
    ".rb",
    ".php",
    ".java",
    ".swift",
    ".kt",
    ".sql",
}

_SOURCE_EXACT_NAMES = {
    "agents.md",
    "claude.md",
    "config.toml",
    "gemini.md",
}

_ALLOWED_DEST_PREFIXES = (
    "/tmp/",
    "/private/tmp/",
    "$TMPDIR/",
    "${TMPDIR}/",
    "/dev/null",
    "/dev/stdout",
    "/dev/stderr",
    "/dev/zero",
)


def _is_disallowed_source_target(target: str) -> bool:
    clean = _strip_redirection(target).strip("'\"")
    if not clean:
        return False
    norm = clean.replace("\\", "/")
    if any(norm == p.rstrip("/") or norm.startswith(p) for p in _ALLOWED_DEST_PREFIXES):
        return False
    base = os.path.basename(norm).lower()
    _, ext = posixpath.splitext(base)
    if ext in _SOURCE_EXTENSIONS or base in _SOURCE_EXACT_NAMES:
        return True
    return False


def _extract_unquoted_redirection_targets(chunk: str) -> list[str]:
    """Extract file targets of unquoted shell redirection operators (>, >>, 1>, 2>, &>)."""
    targets = []
    in_single = False
    in_double = False
    escaped = False
    i = 0
    n = len(chunk)
    while i < n:
        c = chunk[i]
        if escaped:
            escaped = False
            i += 1
            continue
        if c == "\\" and not in_single:
            escaped = True
            i += 1
            continue
        if c == "'" and not in_double:
            in_single = not in_single
            i += 1
            continue
        if c == '"' and not in_single:
            in_double = not in_double
            i += 1
            continue
        if not in_single and not in_double:
            if c == ">":
                j = i + 1
                while j < n and chunk[j] in (">", "&", "|"):
                    j += 1
                while j < n and chunk[j] in (" ", "\t"):
                    j += 1
                target_chars = []
                t_single = False
                t_double = False
                t_escaped = False
                while j < n:
                    tc = chunk[j]
                    if t_escaped:
                        target_chars.append(tc)
                        t_escaped = False
                        j += 1
                        continue
                    if tc == "\\" and not t_single:
                        t_escaped = True
                        j += 1
                        continue
                    if tc == "'" and not t_double:
                        t_single = not t_single
                        j += 1
                        continue
                    if tc == '"' and not t_single:
                        t_double = not t_double
                        j += 1
                        continue
                    if not t_single and not t_double and tc in (" ", "\t", ";", "&", "|", "<", ">", "\n", "\r"):
                        break
                    target_chars.append(tc)
                    j += 1
                if target_chars:
                    targets.append("".join(target_chars))
                i = j
                continue
        i += 1
    return targets


def _check_action_space(command: str, raw_tokens: list[str]) -> SecurityDecision | None:
    tokens = _unwrap_tokens(raw_tokens)
    if not tokens:
        return None

    head = os.path.basename(tokens[0])
    if (
        head not in ("sed", "perl", "perl5", "ruby", "truncate", "tee", "cp", "git")
        and not head.startswith("python")
        and ">" not in command
        and "_tmp_" not in command
    ):
        return None

    # 1. In-place stream editing (sed -i, perl -pi/-i, ruby -i)
    if head == "sed":
        for tok in tokens[1:]:
            clean_tok = _strip_redirection(tok).strip("'\"")
            if clean_tok in ("-i", "--in-place") or clean_tok.startswith("-i") or clean_tok.startswith("--in-place="):
                return SecurityDecision(
                    decision="deny",
                    reason="In-place stream editing via shell is prohibited. Use native file tools (replace_file_content / write_to_file) instead.",
                    category="T7_ACTION_SPACE",
                )

    if head in ("perl", "perl5"):
        for tok in tokens[1:]:
            clean_tok = _strip_redirection(tok).strip("'\"")
            if clean_tok.startswith("-") and not clean_tok.startswith("--") and "i" in clean_tok:
                return SecurityDecision(
                    decision="deny",
                    reason="In-place stream editing via shell is prohibited. Use native file tools (replace_file_content / write_to_file) instead.",
                    category="T7_ACTION_SPACE",
                )

    if head == "ruby":
        for tok in tokens[1:]:
            clean_tok = _strip_redirection(tok).strip("'\"")
            if clean_tok in ("-i",) or clean_tok.startswith("-i") or (clean_tok.startswith("-") and not clean_tok.startswith("--") and "i" in clean_tok):
                return SecurityDecision(
                    decision="deny",
                    reason="In-place stream editing via shell is prohibited. Use native file tools (replace_file_content / write_to_file) instead.",
                    category="T7_ACTION_SPACE",
                )

    # 2. Inline Python file write (python/python3 -c with open(..., 'w'|'a'), .write(, write_text(, write_bytes()
    if head.startswith("python") and any(t == "-c" or t.startswith("-c") for t in tokens[1:]):
        has_open_write = bool(
            re.search(r"""\bopen\s*\([^)]*['"][rwax+]*[wa][rwax+]*['"]""", command)
            or re.search(r"""\bopen\s*\([^)]*mode\s*=\s*['"][rwax+]*[wa][rwax+]*['"]""", command)
        )
        has_write_method = (
            ".write(" in command
            or "write_text(" in command
            or "write_bytes(" in command
        )
        if has_open_write or has_write_method:
            return SecurityDecision(
                decision="deny",
                reason="Writing files via inline python script is prohibited. Use native file tools (write_to_file / replace_file_content) instead.",
                category="T7_ACTION_SPACE",
            )

    # 3. Direct copy mutations into source files (cp ... <source_file>)
    if head == "cp":
        positional = []
        target_dir = None
        idx = 1
        while idx < len(tokens):
            tok = tokens[idx]
            if tok in ("-t", "--target-directory", "-S", "--suffix") and idx + 1 < len(tokens):
                if tok in ("-t", "--target-directory"):
                    target_dir = tokens[idx + 1]
                idx += 2
                continue
            if tok.startswith("--target-directory="):
                target_dir = tok.split("=", 1)[1]
                idx += 1
                continue
            if tok.startswith("-t") and len(tok) > 2 and not tok.startswith("--"):
                target_dir = tok[2:]
                idx += 1
                continue
            if tok.startswith("--suffix=") or (tok.startswith("-S") and len(tok) > 2 and not tok.startswith("--")):
                idx += 1
                continue
            if tok.startswith("-"):
                idx += 1
                continue
            positional.append(tok)
            idx += 1

        if target_dir is not None:
            clean_td = _strip_redirection(target_dir).strip("'\"").replace("\\", "/")
            is_temp_target = any(clean_td == p.rstrip("/") or clean_td.startswith(p) for p in _ALLOWED_DEST_PREFIXES)
            if not is_temp_target:
                for item in positional:
                    if _is_disallowed_source_target(item):
                        return SecurityDecision(
                            decision="deny",
                            reason="Mutating source files via 'cp' is prohibited. Use native file tools (write_to_file / replace_file_content) instead.",
                            category="T7_ACTION_SPACE",
                        )
        elif len(positional) >= 2:
            dest = positional[-1]
            if _is_disallowed_source_target(dest):
                return SecurityDecision(
                    decision="deny",
                    reason="Mutating source files via 'cp' is prohibited. Use native file tools (write_to_file / replace_file_content) instead.",
                    category="T7_ACTION_SPACE",
                )

    # 4. Truncating source files (truncate ... <source_file>)
    if head == "truncate":
        positional = []
        idx = 1
        while idx < len(tokens):
            tok = tokens[idx]
            if tok in ("-s", "--size", "-r", "--reference") and idx + 1 < len(tokens):
                idx += 2
                continue
            if tok.startswith("--size=") or tok.startswith("--reference=") or tok.startswith("-s=") or tok.startswith("-r="):
                idx += 1
                continue
            if tok.startswith("-"):
                idx += 1
                continue
            positional.append(tok)
            idx += 1

        for target in positional:
            if _is_disallowed_source_target(target):
                return SecurityDecision(
                    decision="deny",
                    reason="Truncating source files via 'truncate' is prohibited. Use native file tools (write_to_file / replace_file_content) instead.",
                    category="T7_ACTION_SPACE",
                )

    # 5. Temporary scripts (python3 ... _tmp_*.py, bash ... _tmp_*.sh)
    if "_tmp_" in command:
        for tok in tokens:
            clean = _strip_redirection(tok).strip("'\"")
            base = os.path.basename(clean.replace("\\", "/"))
            if base.startswith("_tmp_") and (
                base.endswith(".py")
                or base.endswith(".sh")
                or base.endswith(".js")
                or base.endswith(".ts")
                or base.endswith(".rb")
                or base.endswith(".pl")
                or base.endswith(".bash")
                or base.endswith(".zsh")
            ):
                return SecurityDecision(
                    decision="deny",
                    reason="Executing temporary _tmp_ scripts is prohibited. Perform operations directly using native tools.",
                    category="T7_ACTION_SPACE",
                )

    # 6. AI co-authorship metadata in commits (Co-Authored-By)
    if "co-authored-by" in command.lower() and head == "git" and any(t == "commit" for t in tokens[1:]):
        return SecurityDecision(
            decision="deny",
            reason="AI co-authorship metadata (Co-Authored-By) in commits is prohibited by policy.",
            category="T7_ACTION_SPACE",
        )

    # 7. Shell redirects (>, >>) and tee utility directed to source files
    if head == "tee":
        for tok in tokens[1:]:
            if tok.startswith("-"):
                continue
            if _is_disallowed_source_target(tok):
                return SecurityDecision(
                    decision="deny",
                    reason="Writing directly to source file via shell redirection/tee is prohibited. Use native file tools (write_to_file / replace_file_content).",
                    category="T7_ACTION_SPACE",
                )

    if ">" in command:
        redir_targets = _extract_unquoted_redirection_targets(command)
        for target in redir_targets:
            if _is_disallowed_source_target(target):
                return SecurityDecision(
                    decision="deny",
                    reason="Writing directly to source file via shell redirection/tee is prohibited. Use native file tools (write_to_file / replace_file_content).",
                    category="T7_ACTION_SPACE",
                )

    return None


_RE_SIMPLE_TOKENS = re.compile(r"""[^\s"']+|"[^"\\]*"|'[^'\\]*'""")


def _fast_tokenize(chunk: str) -> list[str]:
    """Blazing fast tokenizer (<0.005ms) with fallback to regex and shlex."""
    if '"' not in chunk and "'" not in chunk and "\\" not in chunk and "`" not in chunk and "$" not in chunk and "<" not in chunk and ">" not in chunk and "=" not in chunk:
        return chunk.split()
    if "\\" not in chunk and "`" not in chunk and "$" not in chunk and "<" not in chunk and ">" not in chunk and "=" not in chunk:
        parts = chunk.split()
        if len(parts) > 4 and not any(p.startswith('"') or p.startswith("'") or p.endswith('"') or p.endswith("'") for p in parts[3:]):
            return [
                p[1:-1] if (p.startswith('"') and p.endswith('"')) or (p.startswith("'") and p.endswith("'")) else p
                for p in parts
            ]
        matches = _RE_SIMPLE_TOKENS.findall(chunk)
        if matches:
            return [
                m[1:-1] if (m.startswith('"') and m.endswith('"')) or (m.startswith("'") and m.endswith("'")) else m
                for m in matches
            ]
    norm_chunk = _RE_NORM_ATTACHED_REDIR.sub(r" \1 ", chunk)
    return shlex.split(norm_chunk, posix=True)


def _evaluate_chunk(chunk: str) -> SecurityDecision:
    # Fast path for simple safe commands without redirection or special symbols (<0.001ms)
    if not any(c in chunk for c in ("<", ">", "$", "`", "/", "@", "-", ".", "~", ":", "(", ")", "\"", "'")):
        words = chunk.split()
        if words and words[0] in ("true", "false", "pwd", "whoami", "date", "clear"):
            return _DECISION_ALLOW

    tokens = _fast_tokenize(chunk)

    if not tokens:
        return _DECISION_ALLOW

    # 1. T4: Destructive OS mutations & Persistence (Top Priority)
    t4 = _check_destructive_and_persistence(chunk, tokens)
    if t4:
        return t4

    # 2. T3: Obfuscation & Dynamic Eval
    t3 = _check_obfuscation_and_eval(chunk, tokens)
    if t3:
        return t3

    # 3. T2: Network Exfiltration
    t2 = _check_exfiltration(chunk, tokens)
    if t2:
        return t2

    # 4. T1: Sensitive File & Credential Access
    t1 = _check_sensitive_paths(chunk, tokens)
    if t1:
        return t1

    # 5. T5: Supply Chain & Package Insecurity
    t5 = _check_supply_chain(chunk, tokens)
    if t5:
        return t5

    # 6. T7: Action Space Backstop (§26a core-rules)
    t7 = _check_action_space(chunk, tokens)
    if t7:
        return t7

    # 7. T6: High-Risk Git Mutations (Requires 'ask')
    t6 = _check_high_risk_git(chunk, tokens)
    if t6:
        return t6

    # 8. T6: High-Risk Cargo Operations (Requires 'ask')
    t6_cargo = _check_high_risk_cargo(chunk, tokens)
    if t6_cargo:
        return t6_cargo

    # 9. T6: High-Risk Cloud/Infra CLI Mutations (Requires 'ask')
    t6_tools = _check_high_risk_tools(chunk, tokens)
    if t6_tools:
        return t6_tools

    return _DECISION_ALLOW


# ----------------------------------------------------------------------
# Main Public Entrypoint
# ----------------------------------------------------------------------

def _split_into_chunks(command: str) -> list[str]:
    """Split compound command into logical chunks while respecting quotes and lines."""
    lines = [l.strip() for l in command.splitlines() if l.strip()]
    if len(lines) == 1 and not any(op in command for op in (";", "&&", "||", "|", "&")):
        return [command]

    chunks = []
    for line in lines:
        if not any(op in line for op in (";", "&&", "||", "|", "&")):
            chunks.append(line)
            continue
        if '"' not in line and "'" not in line and "\\" not in line and "`" not in line and "$" not in line:
            for part in re.split(r";+|&&|\|\||\||&+", line):
                p = part.strip()
                if p:
                    chunks.append(p)
            continue
        try:
            norm_line = re.sub(r"(?<![&|;'\"])([;&|]{1,2})(?![&|;'\"])", r" \1 ", line)
            raw_tokens = shlex.split(norm_line, posix=True)
        except ValueError:
            chunks.extend(re.split(r";|&&|\|\||\||&", line))
            continue
        curr = []
        for tok in raw_tokens:
            if tok in (";", "&&", "||", "|", "&"):
                if curr:
                    chunks.append(" ".join(shlex.quote(t) for t in curr))
                    curr = []
            elif tok.endswith(";") or tok.endswith("&"):
                stripped = tok.rstrip(";&")
                if stripped:
                    curr.append(stripped)
                if curr:
                    chunks.append(" ".join(shlex.quote(t) for t in curr))
                    curr = []
            else:
                curr.append(tok)
        if curr:
            chunks.append(" ".join(shlex.quote(t) for t in curr))
    return chunks


def evaluate_security(command: str, cwd: str | None = None) -> SecurityDecision:
    """Evaluate a shell command string against the security gatekeeper policies.

    Returns SecurityDecision(decision="allow"|"deny"|"ask", reason=..., category=...).
    Fail-open on internal parser errors to guarantee uninterrupted developer workflow.
    """
    if not command or not isinstance(command, str):
        return _DECISION_ALLOW

    # Length guard
    if len(command) > 4096:
        return SecurityDecision(
            decision="deny",
            reason="Command length exceeds security gate maximum limit (4096 chars)",
            category="T4_DESTRUCTIVE_MUTATION",
        )

    # Shell IFS separator obfuscation normalization
    if "IFS" in command:
        command = re.sub(r"\$\{?IFS\}?", " ", command)

    try:
        # Fast exit for simple long echo/printf commands without triggers (<0.01ms)
        if len(command) > 200 and not any(c in command for c in (";", "&", "|", "<", ">", "$", "`", "\n", "\r", "@", "/", "\"", "'", "\\")):
            first_word = command.split(None, 1)[0] if command.strip() else ""
            if first_word in ("echo", "printf", "true", "false", "pwd", "whoami"):
                return _DECISION_ALLOW

        # Fast global check for fork bombs
        if ":" in command and "{" in command and _RE_FORK_BOMB.search(command):
            return SecurityDecision(
                decision="deny",
                reason="Fork bomb execution pattern detected",
                category="T4_DESTRUCTIVE_MUTATION",
            )

        # Fast global check for pipe to interpreter
        if "|" in command and _RE_PIPE_TO_SHELL.search(command):
            t3 = _check_obfuscation_and_eval(command, [])
            if t3:
                return t3

        # Scoped check for AI co-authorship metadata in git commit commands
        cmd_lower = command.lower()
        if "co-authored-by" in cmd_lower and "git" in cmd_lower and "commit" in cmd_lower:
            return SecurityDecision(
                decision="deny",
                reason="AI co-authorship metadata (Co-Authored-By) in commits is prohibited by policy.",
                category="T7_ACTION_SPACE",
            )

        # Fast global check for shell redirection into source files
        if ">" in command:
            redir_targets = _extract_unquoted_redirection_targets(command)
            for target in redir_targets:
                if _is_disallowed_source_target(target):
                    return SecurityDecision(
                        decision="deny",
                        reason="Writing directly to source file via shell redirection/tee is prohibited. Use native file tools (write_to_file / replace_file_content).",
                        category="T7_ACTION_SPACE",
                    )

        # Split compound commands respecting quotes and newlines
        chunks = _split_into_chunks(command)
        if len(chunks) > 100:
            return SecurityDecision(
                decision="deny",
                reason="Command exceeds maximum chunk complexity (100 operations)",
                category="T4_DESTRUCTIVE_MUTATION",
            )

        decisions = []
        for chunk in chunks:
            chunk = chunk.strip()
            if not chunk:
                continue
            try:
                dec = _evaluate_chunk(chunk)
                if dec.decision == "deny":
                    return dec
                if dec.decision == "ask":
                    decisions.append(dec)
            except ValueError:
                # Malformed syntax fallback
                for bad_pat in (
                    r"\.env\b",
                    r"/\.ssh\b",
                    r"/\.aws\b",
                    r"\beval\s",
                    r"\brm\s+-rf\s+/",
                    r"\bbase64\s+-d\s*\|",
                ):
                    if re.search(bad_pat, chunk):
                        return SecurityDecision(
                            decision="deny",
                            reason="Malformed shell syntax contains prohibited security patterns",
                            category="T1_CREDENTIAL_ACCESS",
                        )

        if decisions:
            return decisions[0]

        return _DECISION_ALLOW

    except Exception:
        return _DECISION_ALLOW
