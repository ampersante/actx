"""actx security gate - T7: action space backstop (core-rules) (TK-59 split).

Body unchanged from the pre-split monolith - see tools/ast_identity_check.py.
"""

import os
import posixpath
import re

from .common import SecurityDecision, _strip_redirection, _unwrap_tokens



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
    ".jsonc",
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
