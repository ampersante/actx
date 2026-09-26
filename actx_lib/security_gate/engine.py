"""actx security gate - evaluation engine: chunk splitting, the per-chunk
dispatch table (_evaluate_chunk) and the public evaluate_security entrypoint
(TK-59 split).

Body unchanged from the pre-split monolith - see tools/ast_identity_check.py.
"""

import re
import shlex

from .common import SecurityDecision, _DECISION_ALLOW, _RE_FORK_BOMB, _RE_PIPE_TO_SHELL
from .t1_paths import _check_sensitive_paths
from .t2_t3 import _check_exfiltration, _check_obfuscation_and_eval
from .t4_destructive import _check_destructive_and_persistence, _check_find_exec_subcommands
from .t5_supply import _check_supply_chain
from .t6_git import _check_high_risk_git
from .t6_tools import (
    _check_high_risk_cargo,
    _check_swiftformat,
    _check_high_risk_npm,
    _check_high_risk_tools,
    _check_gradlew,
)
from .t6_sql import _check_sql
from .t7_action import (
    _check_action_space,
    _extract_unquoted_redirection_targets,
    _is_disallowed_source_target,
)

_RE_CHUNK_SPLIT = re.compile(r";|&&|\|\||\||&|\r?\n")
_RE_NORM_ATTACHED_REDIR = re.compile(r"(?<![0-9])([<>])")


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

    # 1b. T4 (recursive): find -exec/-execdir/-ok/-okdir subcommands
    # (TK-57 S6) - each gets the same or a stricter verdict as standalone.
    t4_find = _check_find_exec_subcommands(tokens)
    if t4_find:
        return t4_find

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

    # 8b. T6: swiftformat in mutating mode (N-F11; no lint/dry flag)
    t6_swiftformat = _check_swiftformat(chunk, tokens)
    if t6_swiftformat:
        return t6_swiftformat

    # 9. T6: High-Risk npm Registry Operations (Requires 'ask')
    t6_npm = _check_high_risk_npm(chunk, tokens)
    if t6_npm:
        return t6_npm

    # 10. T6: High-Risk Cloud/Infra CLI Mutations (Requires 'ask')
    t6_tools = _check_high_risk_tools(chunk, tokens)
    if t6_tools:
        return t6_tools

    # 10b. T6: gradlew publish-class tasks (TK-55 F5) - positional task
    # tokens need the last-":"-segment class, not the exact-token table
    t6_gradlew = _check_gradlew(chunk, tokens)
    if t6_gradlew:
        return t6_gradlew

    # 11. T6: High-Risk SQL payloads (TK-43) - head-specific, runs after the
    # generic verb table (SQL payloads need the classifier, not token specs)
    t6_sql = _check_sql(chunk, tokens)
    if t6_sql:
        return t6_sql

    return _DECISION_ALLOW


# ----------------------------------------------------------------------
# Main Public Entrypoint
# ----------------------------------------------------------------------

# TK-57 S6 (STEP-05, REQ-06): a semicolon that is backslash-escaped or
# quoted is a literal shell argument, not a chunk separator - `find ...
# -exec ... \;` must stay one chunk so its own -exec/;/+' grammar (not the
# naive operator split) decides where each subcommand ends. _mask_literal_
# semicolons runs a single quote/escape-aware pass over the WHOLE command
# before any of the existing operator-detection logic sees it, replacing
# each literal ';' with a sentinel that contains none of the characters
# _split_into_chunks branches on (';', '&', '|', quotes, backslash); the
# rest of the function is unchanged and only ever sees real separators.
# _unmask_literal_semicolons restores ';' in the final chunk strings.
_CHUNK_SEMI_SENTINEL = "\x00ACTX_SEMI\x00"


def _mask_literal_semicolons(text: str) -> str:
    out = []
    i = 0
    n = len(text)
    in_single = False
    in_double = False
    while i < n:
        ch = text[i]
        if in_single:
            if ch == "'":
                in_single = False
                out.append(ch)
            elif ch == ";":
                out.append(_CHUNK_SEMI_SENTINEL)
            else:
                out.append(ch)
            i += 1
            continue
        if in_double:
            if ch == "\\" and i + 1 < n and text[i + 1] in ('"', "\\", "$", "`"):
                out.append(ch)
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_double = False
                out.append(ch)
            elif ch == ";":
                out.append(_CHUNK_SEMI_SENTINEL)
            else:
                out.append(ch)
            i += 1
            continue
        # Outside quotes
        if ch == "'":
            in_single = True
            out.append(ch)
            i += 1
            continue
        if ch == '"':
            in_double = True
            out.append(ch)
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            nxt = text[i + 1]
            if nxt == ";":
                out.append(_CHUNK_SEMI_SENTINEL)
            else:
                out.append(ch)
                out.append(nxt)
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _unmask_literal_semicolons(text: str) -> str:
    return text.replace(_CHUNK_SEMI_SENTINEL, ";")


def _split_into_chunks(command: str) -> list[str]:
    """Split compound command into logical chunks while respecting quotes and lines."""
    command = _mask_literal_semicolons(command)
    lines = [l.strip() for l in command.splitlines() if l.strip()]
    if len(lines) == 1 and not any(op in command for op in (";", "&&", "||", "|", "&")):
        return [_unmask_literal_semicolons(command)]

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
    return [_unmask_literal_semicolons(c) for c in chunks]


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
