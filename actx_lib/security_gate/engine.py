"""actx security gate - evaluation engine: chunk splitting, the per-chunk
dispatch table (_evaluate_chunk) and the public evaluate_security entrypoint
(TK-59 split).

Body unchanged from the pre-split monolith - see tools/ast_identity_check.py.
"""

import os
import re
import shlex
from typing import NamedTuple

from .common import (
    SecurityDecision,
    _DECISION_ALLOW,
    _RE_FORK_BOMB,
    _RE_PIPE_TO_SHELL,
    _WRAPPER_COMMANDS,
    _unwrap_tokens,
)
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
    looks_irreversible,
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


def _evaluate_chunk(chunk: str, exempt: GrammarWords | None = None) -> SecurityDecision:
    # exempt (TK-63): the shell words of a whole single command inside the
    # closed grammar (_closed_grammar_words); only then may T4 and T6 loosen
    # today's verdict. None - the default, so an internal caller such as the
    # find -exec re-evaluation - keeps today's verdict.
    exempt_words = None if exempt is None else exempt.words
    # Fast path for simple safe commands without redirection or special symbols (<0.001ms)
    if not any(c in chunk for c in ("<", ">", "$", "`", "/", "@", "-", ".", "~", ":", "(", ")", "\"", "'")):
        words = chunk.split()
        if words and words[0] in ("true", "false", "pwd", "whoami", "date", "clear"):
            return _DECISION_ALLOW

    tokens = _fast_tokenize(chunk)

    if not tokens:
        return _DECISION_ALLOW

    # 1. T4: Destructive OS mutations & Persistence (Top Priority)
    t4 = _check_destructive_and_persistence(
        chunk, tokens, exempt_words, None if exempt is None else exempt.globs
    )
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
    t6 = _check_high_risk_git(chunk, tokens, exempt_words)
    if t6:
        return t6

    # 8. T6: High-Risk Cargo Operations (Requires 'ask')
    t6_cargo = _check_high_risk_cargo(chunk, tokens, exempt_words)
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
    t6_gradlew = _check_gradlew(chunk, tokens, exempt_words)
    if t6_gradlew:
        return t6_gradlew

    # 11. T6: High-Risk SQL payloads (TK-43) - head-specific, runs after the
    # generic verb table (SQL payloads need the classifier, not token specs)
    t6_sql = _check_sql(chunk, tokens, exempt_words)
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
    if ";" not in text:
        # TK-63 (perf): only ';' is ever replaced; every other char is
        # copied as is, so a text without ';' is returned unchanged.
        return text
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


# TK-63: the closed grammar every loosening requires (owner decision
# 2026-10-22: single simple commands only). The gate does not model shell
# state, so an exemption is computed only on a raw command whose every
# character is in a closed allow-list: then its shell words are exactly
# the shlex words, nothing expands except an anchor (`~/`, `"$HOME/…"`)
# or a final `*` component of a target, and no earlier command or
# assignment can change what the words mean. Anything else keeps today's
# verdict.
_EXEMPTION_HEADS = frozenset({
    "rm", "find", "chmod", "chown", "chgrp", "cargo", "git", "pg_restore",
})
_RE_BARE_WORD = re.compile(r"[A-Za-z0-9._+@%,=:/-]+")
_RE_DOUBLE_QUOTED_BODY = re.compile(r"[A-Za-z0-9._+@%,=:/ -]*")
_RE_SINGLE_QUOTED_BODY = re.compile(r"[A-Za-z0-9._+@%,=:/ *?\[\]-]*")
# Exact whole bare words outside the charset: find's placeholder, its
# escaped terminator and negation.
_BARE_WHOLE_WORDS = {"{}": "{}", "\\;": ";", "!": "!"}
_FIND_LEADING_FLAGS = frozenset({"-H", "-L", "-P", "-E", "-X", "-s", "-x", "-d"})


def _is_exemption_head(word: str) -> bool:
    # gradlew: every spelling _check_gradlew accepts (basename gradlew).
    return word in _EXEMPTION_HEADS or word.rsplit("/", 1)[-1] == "gradlew"


def _bare_word(raw: str) -> tuple[str, bool] | None:
    """(word, has a final `*` component) of an unquoted word inside the
    grammar, or None."""
    if raw in _BARE_WHOLE_WORDS:
        return _BARE_WHOLE_WORDS[raw], False
    if raw.startswith("="):
        return None
    body = raw
    if raw.startswith("~"):
        if raw != "~" and raw[1] != "/":
            return None
        body = raw[1:]
    glob = False
    if "*" in body:
        if not (body == "*" or body.endswith("/*")) or body.count("*") != 1:
            return None
        glob, body = True, body[:-1]
    if body and not _RE_BARE_WORD.fullmatch(body):
        return None
    return raw, glob


def _quoted_word(raw: str) -> str | None:
    body = raw[1:-1]
    if raw[0] == "'":
        return body if body == ";" or _RE_SINGLE_QUOTED_BODY.fullmatch(body) else None
    rest = body
    for anchor in ("$HOME/", "${HOME}/"):
        if body.startswith(anchor):
            rest = body[len(anchor):]
            break
    return body if _RE_DOUBLE_QUOTED_BODY.fullmatch(rest) else None


def _glob_target_indices(words: list[str]) -> set:
    """Word indices where a final `*` component is a T4 target or a find
    starting point; a glob anywhere else is outside the grammar."""
    head = words[0]
    if head == "find":
        out, i = set(), 1
        while i < len(words) and words[i] in _FIND_LEADING_FLAGS:
            i += 1
        while i < len(words) and not words[i].startswith("-") and words[i] != "!":
            out.add(i)
            i += 1
        return out
    if head not in ("rm", "chmod", "chown", "chgrp"):
        return set()
    operands, end_of_options = [], False
    for i in range(1, len(words)):
        if end_of_options or not words[i].startswith("-"):
            operands.append(i)
        elif words[i] == "--":
            end_of_options = True
    # chmod/chown/chgrp: the first operand is the mode/owner, not a target.
    return set(operands if head == "rm" else operands[1:])


class GrammarWords(NamedTuple):
    """Shell words of a command inside the closed grammar, with per-word
    quote provenance: globs[i] is True only when words[i] ends in an
    UNQUOTED `*` component (a target glob); a quoted `*` is literal."""

    words: list[str]
    globs: tuple[bool, ...]


def _closed_grammar_words(command: str) -> GrammarWords | None:
    """The shell words of a single simple command inside the closed grammar,
    or None. Words are separated by spaces; a quoted region is a whole
    word (single quotes: charset, space and `*?[]`, or exactly `';'`;
    double quotes: charset and space after an optional `$HOME/` or
    `${HOME}/`); an unquoted word uses the charset, a leading `~` before
    `/` or the end, one final `*` component, or is exactly `{}`, `\\;`, `!`,
    and never starts with `=`. The first word is an exemption head."""
    # Cheap prefilter only: a head word inside the grammar is bare (ends at
    # the first space) or one whole quoted region (ends at the closing
    # quote, spaces included), so this yields the parsed first word of
    # every command the grammar accepts; that word is validated again below.
    start = len(command) - len(command.lstrip(" "))
    if command[start:start + 1] in ("'", '"'):
        end = command.find(command[start], start + 1)
        first = command[start + 1:end] if end != -1 else ""
    else:
        first = command[start:].split(" ", 1)[0]
    if not _is_exemption_head(first):
        return None
    words, globs = [], []
    i, n = 0, len(command)
    while i < n:
        if command[i] == " ":
            i += 1
            continue
        if command[i] in ("'", '"'):
            end = command.find(command[i], i + 1)
            if end == -1 or (end + 1 < n and command[end + 1] != " "):
                return None
            word = _quoted_word(command[i:end + 1])
            if word is None:
                return None
            words.append(word)
            globs.append(False)
            i = end + 1
            continue
        end = command.find(" ", i)
        end = n if end == -1 else end
        bare = _bare_word(command[i:end])
        if bare is None:
            return None
        words.append(bare[0])
        globs.append(bare[1])
        i = end
    if not words or not _is_exemption_head(words[0]):
        return None
    allowed = _glob_target_indices(words)
    if any(g and idx not in allowed for idx, g in enumerate(globs)):
        return None
    try:
        if shlex.split(command, posix=True) != words:
            return None
    except ValueError:
        return None
    return GrammarWords(words, tuple(globs))


# TK-73: the structural parser (shell_parse) only ADDS evaluations to the
# line-based path of evaluate_security. _needs_parse is a pure cost
# optimisation: the line-based path always runs, so a missed trigger only
# skips the extra closures and never changes today's verdict.
#
# shell_parse is imported on first use: a command without a trigger never
# loads it, which keeps the hook's start-up cost on ordinary commands.
def parse_command(text):
    from . import shell_parse
    return shell_parse.parse_command(text)


def extract_substitutions(text):
    from . import shell_parse
    return shell_parse.extract_substitutions(text)


_RE_PARSE_TRIGGER = re.compile("['\"$`<({#\\\\\\n]")

# Same set as the shell-wrapper branch of t1_paths._check_sensitive_paths
# (a test compares them).
_SHELL_HEADS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh", "fish", "busybox"})
# Heads whose string argument is a command line run by another shell.
_COMMAND_RUNNERS = frozenset({
    "ssh", "mosh", "sshpass", "docker", "podman", "kubectl", "oc", "watch", "script", "su", "runuser",
})
_STRING_EXECUTORS = frozenset({"eval", "source", "."})
_ARGV_EXECUTORS = frozenset({"xargs", "find", "parallel", "sudo", "doas"})
_RE_C_FLAGS = re.compile(r"[-+][A-Za-z]*c[A-Za-z]*$")
_RE_NEWLINE_LIKE = re.compile("[\n\r\x0b\x0c\x85  ]")
_RE_REDIRECT_WORD = re.compile(r"[0-9]*[<>]")
_RE_DURATION_WORD = re.compile(r"\d+[smhd]?$")
_RE_ASSIGN_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\+?=")
_MALFORMED_DENY_PATTERNS = (
    r"\.env\b",
    r"/\.ssh\b",
    r"/\.aws\b",
    r"\beval\s",
    r"\brm\s+-rf\s+/",
    r"\bbase64\s+-d\s*\|",
)
_RDYN_ASK = SecurityDecision(
    decision="ask",
    reason="Nested shell text runs a command word known only at run time (substitution or variable)",
    category="T3_OBFUSCATION_EVAL",
)
_UNPARSED_ASK = SecurityDecision(
    decision="ask",
    reason="actx security gate could not parse the shell structure (unparsed shell structure)",
    category="T6_GATE_ERROR",
)


# Words the parser strips or reads differently while no trigger character
# appears (`coproc rm -rf ~`, `=rm -rf /`, `if x; then rm -rf /; fi`).
_PARSE_KEYWORDS = frozenset(
    "! if then elif else while until do for select case function coproc repeat nocorrect noglob".split()
)
_WORD_SEPARATORS = str.maketrans({c: " " for c in ";&|()"})


def _has_parse_word(command: str) -> bool:
    # A word-level scan (split) is several times cheaper than a regex on
    # long inputs. Separators count on both sides (a harmless superset).
    words = command.translate(_WORD_SEPARATORS).split()
    if not _PARSE_KEYWORDS.isdisjoint(words):
        return True
    return "=" in command and any(
        w[0] == "=" and len(w) > 1 and (w[1].isalnum() or w[1] == "_") for w in words
    )


def _needs_parse(command: str) -> bool:
    return _RE_PARSE_TRIGGER.search(command) is not None or _has_parse_word(command)


_RE_PLAIN_QUOTED = re.compile(r"(?<!\S)([\'\"])([A-Za-z0-9_./=:,@%+-]+)\1(?!\S)")


def _heredoc_covers(chunk: str, parsed) -> bool:
    """True when the chunk is a piece of a heredoc body line."""
    needle = chunk.strip().replace("\\", "")
    return any(needle in line for line in parsed.heredoc_body_lines)


def _run_chunk(chunk, exempt, decisions, parsed=None, broad=False, done=None, dropped=None):
    """Evaluate one chunk (a line-based chunk or a parser unit): returns a
    deny decision or None and appends an ask to decisions. A failure in the
    chunk never discards the rest (broad: any exception, for parser units).
    done: collects (chunk, exempt-or-not) of evaluations that completed, so
    a parser unit equal to an already judged chunk is not judged twice."""
    try:
        dec = _evaluate_chunk(chunk, exempt)
        if done is not None:
            done.add((chunk, exempt is None))
            # A unit that only differs by quotes around plain whole words
            # (`'TODO'` -> `TODO`) is judged by this same evaluation.
            if "'" in chunk or '"' in chunk:
                done.add((_RE_PLAIN_QUOTED.sub(r"\2", chunk), exempt is None))
        if dec.decision == "deny":
            return dec
        if dec.decision == "ask":
            decisions.append(dec)
    except (Exception if broad else ValueError) as exc:
        # Malformed syntax fallback
        for bad_pat in _MALFORMED_DENY_PATTERNS:
            if re.search(bad_pat, chunk):
                return SecurityDecision(
                    decision="deny",
                    reason="Malformed shell syntax contains prohibited security patterns",
                    category="T1_CREDENTIAL_ACCESS",
                )
        # REQ-04 (TK-70): a parser failure on an irreversible chunk
        # asks instead of falling through to the default allow; every
        # other chunk keeps the previous fallback. The ask joins the
        # normal ask list so a later chunk's deny still wins (the
        # engine's deny > ask > allow precedence).
        # TK-73: after a successful parse, a chunk that is not a piece of
        # a heredoc body line is a fragment of a multi-line quote; the
        # parser's units judge it, so no gate-error ask for it.
        if looks_irreversible(chunk):
            ask = SecurityDecision(
                decision="ask",
                reason=f"actx security gate internal error on irreversible command: {exc}",
                category="T6_GATE_ERROR",
            )
            if parsed is None or _heredoc_covers(chunk, parsed):
                decisions.append(ask)
            elif dropped is not None:
                dropped.append(ask)
    return None


class _Seen(set):
    """Nested texts judged so far by one top-level call, and their size."""

    chars = 0


_MAX_NESTED_CHARS = 12_000
_NESTED_LIMIT_ASK = SecurityDecision(
    decision="ask",
    reason="actx security gate stopped checking an excessively nested command (nested structure too large)",
    category="T6_GATE_ERROR",
)


def _eval_nested(text, cwd, seen, decisions, rdyn=True):
    """Whole-gate evaluation of a text the shell runs as commands. seen is
    shared by the whole recursion of one top-level call: the evaluation is
    pure and every verdict reaches the top, so a repeat adds nothing (and
    nested `$((` would otherwise re-evaluate the same texts exponentially)."""
    key = (text, rdyn)
    if key in seen or not text.strip():
        return None
    # Total size of the nested texts judged by one top-level call: a
    # pathological nesting has quadratically many distinct substrings.
    seen.chars += len(text)
    if seen.chars > _MAX_NESTED_CHARS:
        decisions.append(_NESTED_LIMIT_ASK)
        return None
    seen.add(key)
    try:
        dec = evaluate_security(text, cwd, _nested=True, _seen=seen, _rdyn=rdyn)
    except Exception:
        return None
    if dec.decision == "deny":
        return dec
    if dec.decision == "ask":
        decisions.append(dec)
    return None


def _c_operand(tokens, j):
    """The operand of the `-c` option of the shell at tokens[j], or None."""
    k = j + 1
    while k < len(tokens) and tokens[k][:1] in "-+" and tokens[k] not in ("-", "+", "--"):
        if tokens[k] in ("-o", "+o", "-O", "+O"):
            k += 2
            continue
        if _RE_C_FLAGS.match(tokens[k]):
            return tokens[k + 1] if k + 1 < len(tokens) else None
        k += 1
    return None


def _head_index(tokens):
    """Index of the command a unit's words run after env assignments and
    wrapper commands, skipping each wrapper's options together with their
    values (`timeout -s KILL 5 sh`), or None."""
    from .shell_parse import _WRAPPER_VALUE_OPTIONS

    i, n = 0, len(tokens)
    while i < n:
        t = tokens[i]
        base = os.path.basename(t)
        if _RE_ASSIGN_WORD.match(t):
            i += 1
        elif _RE_REDIRECT_WORD.match(t):
            i += 1 if t.lstrip("0123456789").strip("<>&") else 2  # operator alone: target follows
        elif base in _WRAPPER_COMMANDS:
            value_opts = _WRAPPER_VALUE_OPTIONS.get(base, ())
            duration = base == "timeout"  # its first positional operand
            i += 1
            while i < n:
                t = tokens[i]
                if t.startswith("-"):
                    i += 2 if t in value_opts else 1
                elif "=" in t or _RE_DURATION_WORD.match(t) or duration:
                    duration = False
                    i += 1
                else:
                    break
        else:
            return i
    return None


def _shell_word(word, any_word=False):
    """A shell, or a word that starts with one (`sh -c ...`); with any_word,
    a word holding one anywhere (`env -S "/usr/bin/env bash -c ..."`)."""
    parts = word.split()
    if not any_word:
        parts = parts[:1]
    return any(os.path.basename(p) in _SHELL_HEADS for p in parts)


def _shell_bodies(unit):
    """Words of a unit that a shell runs as a command line (INV-10), only
    where the unit's command really executes them: a word with a newline-like
    character when the head is a shell, eval/source/., a command runner or an
    argv executor (xargs, find, sudo, ...); and, for a shell that the unit
    itself starts (directly or through such an executor), the operand of its
    `-c` option, whatever quotes it holds (the canonical unit text re-quotes
    it in a form the line-based checks mis-tokenise). Other arguments of the
    shell (script names, script arguments) are data."""
    if not unit.multiline:
        return ()
    try:
        tokens = shlex.split(unit.text)
    except ValueError:
        return unit.multiline
    try:
        rest = _unwrap_tokens(tokens)
    except Exception:
        rest = []
    heads = set()
    plain = list(tokens)
    while plain and _RE_ASSIGN_WORD.match(plain[0]):
        plain.pop(0)
    if plain:
        heads.add(os.path.basename(plain[0]))
    if rest:
        heads.add(os.path.basename(rest[0]))
    head_at = _head_index(tokens)
    if head_at is not None:
        heads.add(os.path.basename(tokens[head_at]))
    direct = bool(heads & _SHELL_HEADS)
    via = bool(heads & _ARGV_EXECUTORS)
    # A shell word among the unit's own words (a quoted value counts only as
    # the value of env's -S) and a head the option skipping did not resolve
    # (an unknown wrapper, a redirection, `env -S "sh -c ..."`): which operand
    # the shell runs is unknown, so every newline-like value counts as a body
    # (stricter).
    ambiguous = any(
        _shell_word(
            t[2:] if t.startswith("-S") else t,
            t.startswith("-S") or bool(k and tokens[k - 1] in ("-S", "--split-string")),
        )
        for k, t in enumerate(tokens)
        if t not in unit.multiline or t.startswith("-S") or (k and tokens[k - 1] in ("-S", "--split-string"))
    )
    if not (direct or via or ambiguous or heads & (_COMMAND_RUNNERS | _STRING_EXECUTORS)):
        return ()
    bodies = [v for v in unit.multiline if _RE_NEWLINE_LIKE.search(v)]
    starts = []
    for k in {head_at, tokens.index(rest[0]) if rest and rest[0] in tokens else None}:
        if k is not None and os.path.basename(tokens[k]) in _SHELL_HEADS:
            starts.append(k)
    if via:
        starts += [k for k, t in enumerate(tokens) if os.path.basename(t) in _SHELL_HEADS]
    for k in starts:
        operand = _c_operand(tokens, k)
        if operand is not None and operand in unit.multiline and operand not in bodies:
            bodies.append(operand)
    return tuple(bodies)


def _rdyn_check(unit, nested, rdyn=True):
    """INV-09: inside a nested evaluation a command word known only at run
    time (substitution or variable) asks. rdyn is False for the alternative
    reading of an arithmetic expansion (`$(( $a + 1 ))` read as `( $a + 1 )`):
    a hedge, not a command the shell runs."""
    return _RDYN_ASK if nested and rdyn and unit.dyn_head else None


def _evaluate_parsed(parsed, cwd, exempt, nested, decisions, done, seen, rdyn):
    """R1-R3 of evaluate_security: parser units (with dialect variants),
    nested texts and shell bodies. Returns a deny decision or None; asks
    are appended to decisions."""
    if "|" in parsed.canonical and _RE_PIPE_TO_SHELL.search(parsed.canonical):
        try:
            t3 = _check_obfuscation_and_eval(parsed.canonical, [])
        except Exception:
            t3 = None
        if t3:
            if t3.decision == "deny":
                return t3
            decisions.append(t3)
    # TK-63: a unit gets the exemption only when it is the sole command.
    unit_exempt = exempt if len(parsed.units) == 1 and not parsed.nested else None
    items = [(u.pos, 0, u) for u in parsed.units] + [(nd.pos, 1, nd) for nd in parsed.nested]
    items.sort(key=lambda it: (it[0], it[1]))
    for _pos, kind, item in items:
        if kind == 1:
            dec = _eval_nested(item.text, cwd, seen, decisions, item.kind != "arith_alt")
            if dec:
                return dec
            continue
        ask = _rdyn_check(item, nested, rdyn)
        if ask:
            decisions.append(ask)
        text = item.text.strip()
        if text and (text, unit_exempt is None) not in done:
            dec = _run_chunk(text, unit_exempt, decisions, broad=True)
            if dec:
                return dec
        for body in _shell_bodies(item):
            dec = _eval_nested(body, cwd, seen, decisions)
            if dec:
                return dec
    return None


def _evaluate_unparsed(command, cwd, nested, decisions, seen):
    """INV-02: the parser gave up; the line-based path already ran, and the
    bodies a plain scan finds in substitutions go to the whole gate. At the
    top level an unbalanced substitution asks."""
    bodies = extract_substitutions(command)
    if bodies is None:
        if not nested and any(m in command for m in ("$(", "`", "<(", ">(")):
            decisions.append(_UNPARSED_ASK)
        return None
    for body in bodies:
        dec = _eval_nested(body, cwd, seen, decisions)
        if dec:
            return dec
    return None


def evaluate_security(
    command: str, cwd: str | None = None, *, _nested: bool = False, _seen=None, _rdyn: bool = True
) -> SecurityDecision:
    """Evaluate a shell command string against the security gatekeeper policies.

    Returns SecurityDecision(decision="allow"|"deny"|"ask", reason=..., category=...).
    Fail-open on internal parser errors to guarantee uninterrupted developer workflow.
    _nested: a recursive call from inside the gate (`sh -c` body); it never
    gets the TK-63 exemptions. _seen, _rdyn: private state of that recursion
    (evaluated nested texts; whether R-DYN applies to this call's units).
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

    raw_command = command

    # Shell IFS separator obfuscation normalization
    if "IFS" in command:
        command = re.sub(r"\$\{?IFS\}?", " ", command)

    try:
        # Fast exit for simple long echo/printf commands without triggers (<0.01ms)
        if len(command) > 200 and not any(c in command for c in (";", "&", "|", "<", ">", "$", "`", "\n", "\r", "@", "/", "\"", "'", "\\")):
            first_word = command.split(None, 1)[0] if command.strip() else ""
            if first_word in ("echo", "printf", "true", "false", "pwd", "whoami"):
                return _DECISION_ALLOW

        # TK-63: words for the exemptions, or None (today's verdict) for a
        # nested evaluation or a command outside the closed grammar.
        exempt = None if _nested else _closed_grammar_words(raw_command)

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

        if exempt is not None and sum(1 for c in chunks if c.strip()) != 1:
            exempt = None

        # TK-73: one structural parse (the trigger is a cost optimisation
        # only); None after a trigger means the parser gave up (INV-02).
        triggered = _needs_parse(command)
        try:
            parsed = parse_command(command) if triggered else None
        except Exception:
            parsed = None

        decisions = []
        done = set()
        dropped = []
        seen = _Seen() if _seen is None else _seen
        for chunk in chunks:
            chunk = chunk.strip()
            if not chunk:
                continue
            dec = _run_chunk(chunk, exempt, decisions, parsed, done=done, dropped=dropped)
            if dec:
                return dec

        # An error while adding the parser's evaluations must not drop the
        # line-based verdict (it stands as the pre-TK-73 gate gave it).
        dec = None
        try:
            if parsed is not None:
                dec = _evaluate_parsed(parsed, cwd, exempt, _nested, decisions, done, seen, _rdyn)
            elif triggered:
                dec = _evaluate_unparsed(command, cwd, _nested, decisions, seen)
        except Exception:
            # The T6 asks R0 dropped for multi-line quote fragments relied on
            # this parse: keep them.
            decisions.extend(dropped)
            dec = None
        if dec:
            return dec

        if decisions:
            return decisions[0]

        return _DECISION_ALLOW

    except Exception as exc:
        # REQ-04 (TK-70): the same ask for the whole-command failure path;
        # every other command keeps the fail-open allow.
        if looks_irreversible(command):
            return SecurityDecision(
                decision="ask",
                reason=f"actx security gate internal error on irreversible command: {exc}",
                category="T6_GATE_ERROR",
            )
        return _DECISION_ALLOW
