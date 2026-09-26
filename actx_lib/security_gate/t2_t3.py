"""actx security gate - T2/T3: network exfiltration + shell obfuscation/eval
(TK-59 split).

Body unchanged from the pre-split monolith - see tools/ast_identity_check.py.
"""

import os
import re
import shlex

from .common import SecurityDecision, _unwrap_tokens, _RE_EXFIL_VARS, _RE_PIPE_TO_SHELL
from .t1_paths import _is_sensitive_path


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
_RE_PROCESS_SUBST = re.compile(
    r"(?:sh|bash|zsh|dash|ksh|source|\.|\btemp\b|\btee\b)\s+(?:-[a-zA-Z0-9_\-]+\s+)*(?:<\s*)?[<>]?\(\s*(?:curl|wget|fetch|base64|xxd|echo|printf|cat|head|tail|gzip|gunzip|tar|openssl)",
    re.IGNORECASE,
)
_RE_INLINE_SOCKET = re.compile(
    r"(python|python3|perl|ruby|node|nodejs|php)\s+.*(-c|-e|-r|--eval)\s+.*(socket|subprocess\.Popen|pty\.spawn|connect\(|fsockopen)",
    re.IGNORECASE | re.DOTALL,
)


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
