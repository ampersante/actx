import json
import shlex
import sys

import actx_lib.conventions as conventions
import actx_lib.rewriter as rewriter
import actx_lib.security_gate as security_gate

ALLOWED_TOOLS = {"Bash", "bash", "Shell", "shell", "exec", "terminal", "pwsh"}

ADDITIONAL_CONTEXT = "Command rewritten by actx for output compression."

_AGY_DEFER_REASON = "actx: command outside actx policy — deferred to user confirmation"

_GATE_ERROR_REASON = (
    "actx security gate internal error on irreversible command"
)

# Human gate-confirmation texts (ask paths only): the command, one plain
# sentence about what that command class does, and the gate's rule reason.
# One static sentence per category that is not `T6_HIGH_RISK_<HEAD>`; a
# head-named category is covered by _HUMAN_ASK_FAMILY, so a new table head
# needs no new sentence. `T6_GATE_ERROR` appends the sanitized exception.
# Model-facing texts (deny, ask_as_deny) do not use this table.
_HUMAN_ASK = "actx security gate confirmation required"

_HUMAN_ASK_EXPLANATIONS = {
    "T4_DESTRUCTIVE_MUTATION":
        "deletes or overwrites files and local state and cannot be undone",
    "T5_SUPPLY_CHAIN":
        "installs or updates packages — third-party code will run on this "
        "machine",
    "T6_HIGH_RISK_GIT":
        "rewrites remote git history or refs and can affect what everyone "
        "else sees",
    "T6_HIGH_RISK_CARGO":
        "publishes a Rust crate or changes crates.io state",
    "T6_HIGH_RISK_SWIFTFORMAT":
        "rewrites Swift source files in place",
    "T6_HIGH_RISK_GRADLEW":
        "publishes build artifacts or deletes build outputs",
    "T6_HIGH_RISK_SQL":
        "changes database rows or schema",
    "T6_GATE_ERROR":
        "the security gate could not finish checking this command, so it "
        "needs a human decision",
}

_HUMAN_ASK_FAMILY_PREFIX = "T6_HIGH_RISK_"
_HUMAN_ASK_FAMILY = (
    "runs {head} in a mode that can change remote state, publish artifacts, "
    "or deploy a service"
)
_HUMAN_ASK_FALLBACK = (
    "runs a command class that the security gate asks a human to review"
)

# A long command keeps its first 70 and last 40 characters so a trailing
# trigger stays visible; the marker names the hidden char count and flags a
# hidden compound separator. shlex.quote is applied after truncation so the
# displayed command is always one well-formed shell word.
_HUMAN_ASK_COMMAND_MAX = 120
_HUMAN_ASK_COMMAND_HEAD = 70
_HUMAN_ASK_COMMAND_TAIL = 40
_HUMAN_ASK_REASON_MAX = 120
_HUMAN_ASK_COMPOUND = ("&&", "||", ";", "|")
_CONTROL_TO_SPACE = {
    code: " " for code in [*range(0x20), 0x7f, *range(0x80, 0xa0)]
}


# Per-agent policy for the Claude/Codex schema (TK-65, `actx hook --agent
# <name>`); a Codex turn_id selects codex when no agent is specified.
# None = the default policy. The gate runs first for every agent.
#   ask_as_deny: the agent has no confirmation channel - a gate "ask" is
#                emitted as "deny" with the gate's reason.
#   mutator:     a rewritable git mutator (rewriter.is_mutator):
#                "rewrite" - allow + updatedInput, like any other rewrite;
#                "none"    - no output: the harness's own rules see the
#                            command as typed (Codex, OpenCode);
#                "allow"   - allow without updatedInput: auto-allowed as
#                            today, rules see the typed string (Devin, whose
#                            empty response would prompt; `-p` rejects).
#   push:        a rewritable `git push` (rewriter.is_git_push), decided
#                before the mutator policy: "defer" - no verdict at all, the
#                harness's own confirmation stays in force (TK-70 REQ-01).
#   output:      how a verdict is shaped: "claude" (default) - the
#                hookSpecificOutput object; "hermes" - the flat Hermes
#                shell-hook shapes ({"decision": "block"|"modify", ...},
#                {"action": "approve", ...}); no additionalContext, no hints.
#   gate_only:   True - never reach the rewriter: the gate verdicts (deny/ask)
#                pass through in the claude schema and every other outcome is
#                no output (dsh; its mutator/push rows are unreachable and
#                kept for row-form uniformity).
AGENT_POLICIES = {
    None: {"ask_as_deny": False, "mutator": "rewrite", "push": "defer"},
    "codex": {"ask_as_deny": False, "mutator": "none", "push": "defer"},
    "opencode": {"ask_as_deny": True, "mutator": "none", "push": "defer"},
    "devin": {"ask_as_deny": False, "mutator": "allow", "push": "defer"},
    "pi": {"ask_as_deny": True, "mutator": "rewrite", "push": "defer"},
    "hermes": {"ask_as_deny": False, "mutator": "none", "push": "defer", "output": "hermes"},
    "dsh": {"ask_as_deny": False, "mutator": "none", "push": "defer", "gate_only": True},
}


def _gate_error_reason(exc):
    return f"{_GATE_ERROR_REASON}: {exc}"


def _error_is_irreversible(command):
    """REQ-04 (TK-70): a gate failure asks instead of failing open when the
    command is irreversible - any T6-ask command (looks_irreversible) or an
    ordinary `git push`, which actx never lets through as an allow (REQ-01).
    Both predicates return True on their own failure (safe side)."""
    return (security_gate.looks_irreversible(command)
            or rewriter.is_git_push(command))


def _push_defers(command):
    """True for a rewritable `git push`: actx withholds its verdict so the
    harness's native confirmation stays in force (TK-70 REQ-01)."""
    return rewriter.is_mutator(command) and rewriter.is_git_push(command)


def _gate_reason(prefix, category, reason):
    if category:
        return f"{prefix} [{category}]: {reason}"
    return f"{prefix}: {reason}"


def _cap(text, limit=_HUMAN_ASK_REASON_MAX):
    if len(text) <= limit:
        return text
    return text[:limit - 1] + "…"


def _shown_command(command):
    """The command as one shlex-quoted shell word. A command longer than
    _HUMAN_ASK_COMMAND_MAX keeps its first 70 and last 40 characters; the
    marker carries the hidden char count, and a hidden `&&`/`||`/`;`/`|`
    marks the shown fragment as a partial compound command."""
    if len(command) > _HUMAN_ASK_COMMAND_MAX:
        hidden = command[_HUMAN_ASK_COMMAND_HEAD:-_HUMAN_ASK_COMMAND_TAIL]
        if any(sep in hidden for sep in _HUMAN_ASK_COMPOUND):
            marker = (
                f"…(+{len(hidden)} chars, compound command partially shown)…"
            )
        else:
            marker = f"…(+{len(hidden)} chars)…"
        command = (
            command[:_HUMAN_ASK_COMMAND_HEAD]
            + marker
            + command[-_HUMAN_ASK_COMMAND_TAIL:]
        )
    return shlex.quote(command)


def _sanitized_exc(reason):
    """The exception detail of a T6_GATE_ERROR reason, made printable: a
    control character becomes a space and the result is capped at 120."""
    prefix = _GATE_ERROR_REASON + ": "
    exc = reason[len(prefix):] if reason.startswith(prefix) else reason
    return _cap(exc.translate(_CONTROL_TO_SPACE))


def _explanation(category, reason):
    text = _HUMAN_ASK_EXPLANATIONS.get(category)
    if text is not None:
        if category == "T6_GATE_ERROR":
            text += f" (internal error: {_sanitized_exc(reason or '')})"
        return text
    if category and category.startswith(_HUMAN_ASK_FAMILY_PREFIX):
        head = category[len(_HUMAN_ASK_FAMILY_PREFIX):].lower()
        if head:
            return _HUMAN_ASK_FAMILY.format(head=head)
    return _HUMAN_ASK_FALLBACK


def _human_ask_message(command, category, reason):
    """Human-facing gate-confirmation text: the command, a plain-language
    explanation of the category, and the gate rule reason. Used only where
    a human decides (claude-schema ask, hermes approve, agy force_ask)."""
    category_part = f" [{category}]" if category else ""
    return (
        f"{_HUMAN_ASK}{category_part} {_shown_command(command)}: "
        f"{_explanation(category, reason)} — {_cap(reason or '')}"
    )


def process(text, agent=None):
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        print("actx hook: invalid JSON", file=sys.stderr)
        return None

    if not isinstance(data, dict):
        print("actx hook: input is not a JSON object", file=sys.stderr)
        return None

    # Antigravity CLI (gemini) schema
    if "toolCall" in data:
        tool_call = data.get("toolCall")
        if not isinstance(tool_call, dict) or tool_call.get("name") != "run_command":
            print("actx hook: missing or unsupported toolCall name", file=sys.stderr)
            return None
        args = tool_call.get("args")
        if not isinstance(args, dict):
            print("actx hook: toolCall args is not an object", file=sys.stderr)
            return None
        command = args.get("CommandLine")
        if not isinstance(command, str):
            print("actx hook: CommandLine is missing or not a string", file=sys.stderr)
            return None

        try:
            sec_res = security_gate.evaluate_security(command)
        except Exception as exc:
            # REQ-04 (TK-70): a gate failure on an irreversible command asks
            # (force_ask is the Antigravity ask equivalent); every other
            # command keeps the fail-open deferral.
            if not _error_is_irreversible(command):
                return None
            return {
                "decision": "force_ask",
                "reason": _human_ask_message(
                    command, "T6_GATE_ERROR", _gate_error_reason(exc)),
            }

        if sec_res is not None:
            if sec_res.decision == "deny":
                return {
                    "decision": "deny",
                    "reason": sec_res.reason,
                }
            if sec_res.decision == "ask":
                return {
                    "decision": "force_ask",
                    "reason": _human_ask_message(
                        command, sec_res.category, sec_res.reason),
                }

        try:
            rewritten = rewriter.rewrite(command)
        except Exception:
            rewritten = None

        if rewritten is not None and not _push_defers(command):
            return {
                "decision": "allow",
                "overwrite": {"CommandLine": rewritten},
            }
        # Fallthrough: no gate verdict, no rewrite - also an ordinary push
        # (REQ-01: never auto-approved). Empty hook output is
        # undocumented in the Antigravity contract and third-party sources
        # report it as fail-closed, while "deny" would break every
        # unrewritten command - so "ask" is used as the defer primitive:
        # it prompts the user but honors the "Always Allow" cache, unlike
        # "force_ask" which would bypass it.
        return {"decision": "ask", "reason": _AGY_DEFER_REASON}

    # Claude Code / Codex CLI schema
    tool_name = data.get("tool_name") or (
        data.get("toolUse", {}).get("name")
        if isinstance(data.get("toolUse"), dict)
        else None
    )
    if tool_name not in ALLOWED_TOOLS:
        print("actx hook: missing or unsupported tool_name", file=sys.stderr)
        return None

    tool_input = data.get("tool_input") or (
        data.get("toolUse", {}).get("input")
        if isinstance(data.get("toolUse"), dict)
        else None
    )
    if not isinstance(tool_input, dict):
        print("actx hook: tool_input is not an object", file=sys.stderr)
        return None

    command = tool_input.get("command")
    if not isinstance(command, str):
        print("actx hook: command is missing or not a string", file=sys.stderr)
        return None

    # The policy is resolved before the gate so the gate-error path below
    # emits its ask through the same mapping as a gate ask (REQ-04, TK-70):
    # a Codex turn_id selects the codex policy, and opencode/pi turn the
    # ask into a deny with their standard reason.
    turn_id = data.get("turn_id")
    if agent is None and isinstance(turn_id, str) and turn_id:
        agent = "codex"
    policy = AGENT_POLICIES.get(agent, AGENT_POLICIES[None])
    output = policy.get("output", "claude")

    # 1. Evaluate Security Gatekeeper policies
    try:
        sec_res = security_gate.evaluate_security(command)
    except Exception as exc:
        # REQ-04 (TK-70): a gate failure on an irreversible command asks
        # instead of failing open; every other command keeps the fail-open
        # deferral to native harness permissions.
        if not _error_is_irreversible(command):
            return None
        sec_res = security_gate.SecurityDecision(
            decision="ask",
            reason=_gate_error_reason(exc),
            category="T6_GATE_ERROR",
        )

    if sec_res is not None:
        if sec_res.decision == "deny":
            reason = _gate_reason(
                "actx security gate violation", sec_res.category, sec_res.reason)
            if output == "hermes":
                return {"decision": "block", "reason": reason}
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": reason,
                }
            }

        if sec_res.decision == "ask" and policy["ask_as_deny"]:
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": _gate_reason(
                        f"actx security gate ({agent}: no confirmation channel)",
                        sec_res.category, sec_res.reason),
                }
            }

        if sec_res.decision == "ask":
            message = _human_ask_message(
                command, sec_res.category, sec_res.reason)
            if output == "hermes":
                return {"action": "approve", "message": message}
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "ask",
                    "permissionDecisionReason": message,
                }
            }

    # dsh (gate_only): the gate verdict is the whole policy - never reach the
    # rewriter, so no allow and no updatedInput are ever produced.
    if policy.get("gate_only", False):
        return None

    # 2. Output compression rewrite (for safe/allowed commands)
    try:
        rewritten = rewriter.rewrite(command)
    except Exception:
        rewritten = None

    if rewritten is None:
        # Clean/safe command without compression -> strictly return None
        # to defer to the agent harness's native permission policy
        return None

    # REQ-01 (TK-70): an ordinary push gets no verdict before the mutator
    # policy - no allow, no updatedInput, no overwrite - so the harness's
    # own confirmation stays in force on every agent.
    if (rewritten is not None and _push_defers(command)
            and policy["push"] == "defer"):
        return None

    if policy["mutator"] != "rewrite" and rewriter.is_mutator(command):
        if policy["mutator"] == "none":
            return None
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
            }
        }

    updated_input = dict(tool_input)
    updated_input["command"] = rewritten

    # Hermes shell-hook contract: a rewrite is a flat "modify" carrying the
    # full tool_input; the contract has no additionalContext field, so the
    # conventions hint is never computed on this path.
    if output == "hermes":
        return {"decision": "modify", "tool_input": updated_input}

    # TK-45: compact-flag hint (REQ-03) - allow+rewrite verdict ONLY, in
    # its own try/except: any conventions failure degrades to the plain
    # additionalContext (fail-open, INV-05). Not on deny/ask, not on the
    # Antigravity schema (no additionalContext field in that contract).
    hint = None
    try:
        hint = conventions.hint_for(command)
    except Exception:
        hint = None

    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
            "updatedInput": updated_input,
            "additionalContext": ADDITIONAL_CONTEXT + ("\n" + hint if hint else ""),
        }
    }


def _parse_args(argv):
    """(agent, payload) from `hook` argv, parsed by hand in any order.
    `--agent <name>` selects AGENT_POLICIES; an unknown name, a trailing
    `--agent` or any unknown token -> agent None (payload-selected policy).
    `--payload <json>` replaces stdin; a trailing `--payload` -> "" (not
    JSON -> no output). payload None = read stdin."""
    agent = None
    payload = None
    known = True
    i = 0
    while i < len(argv):
        tok = argv[i]
        if tok == "--agent" and i + 1 < len(argv):
            agent = argv[i + 1]
            i += 2
        elif tok == "--payload":
            payload = argv[i + 1] if i + 1 < len(argv) else ""
            i += 2
        else:
            known = False
            i += 1
    if not known or agent not in AGENT_POLICIES:
        agent = None
    return agent, payload


def main(argv=()):
    agent, text = _parse_args(list(argv))
    if text is None:
        try:
            text = sys.stdin.read()
        except OSError:
            print("actx hook: failed to read stdin", file=sys.stderr)
            return 1
    result = process(text, agent)
    if result is not None:
        try:
            json.dump(result, sys.stdout)
            sys.stdout.write("\n")
        except (OSError, ValueError):
            print("actx hook: failed to write response", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
