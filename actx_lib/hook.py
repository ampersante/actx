import json
import sys

import actx_lib.conventions as conventions
import actx_lib.rewriter as rewriter
import actx_lib.security_gate as security_gate

ALLOWED_TOOLS = {"Bash", "bash", "Shell", "shell", "exec"}

ADDITIONAL_CONTEXT = "Command rewritten by actx for output compression."

_AGY_DEFER_REASON = "actx: command outside actx policy — deferred to user confirmation"

# Per-agent policy for the Claude/Codex schema (TK-65, `actx hook --agent
# <name>`); None = no --agent, today's behaviour. The gate runs first for
# every agent.
#   ask_as_deny: the agent has no confirmation channel - a gate "ask" is
#                emitted as "deny" with the gate's reason.
#   mutator:     a rewritable git mutator (rewriter.is_mutator):
#                "rewrite" - allow + updatedInput, like any other rewrite;
#                "none"    - no output: the harness's own rules see the
#                            command as typed (OpenCode);
#                "allow"   - allow without updatedInput: auto-allowed as
#                            today, rules see the typed string (Devin, whose
#                            empty response would prompt; `-p` rejects).
AGENT_POLICIES = {
    None: {"ask_as_deny": False, "mutator": "rewrite"},
    "opencode": {"ask_as_deny": True, "mutator": "none"},
    "devin": {"ask_as_deny": False, "mutator": "allow"},
    "pi": {"ask_as_deny": True, "mutator": "rewrite"},
}


def _gate_reason(prefix, category, reason):
    if category:
        return f"{prefix} [{category}]: {reason}"
    return f"{prefix}: {reason}"


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
        except Exception:
            return None

        if sec_res is not None:
            if sec_res.decision == "deny":
                return {
                    "decision": "deny",
                    "reason": sec_res.reason,
                }
            if sec_res.decision == "ask":
                return {
                    "decision": "force_ask",
                    "reason": sec_res.reason,
                }

        try:
            rewritten = rewriter.rewrite(command)
        except Exception:
            rewritten = None

        if rewritten is not None:
            return {
                "decision": "allow",
                "overwrite": {"CommandLine": rewritten},
            }
        # Fallthrough: no gate verdict, no rewrite. Empty hook output is
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

    # 1. Evaluate Security Gatekeeper policies
    try:
        sec_res = security_gate.evaluate_security(command)
    except Exception:
        # Fail-open guarantee: defer to native harness permissions on gate error
        return None

    policy = AGENT_POLICIES.get(agent, AGENT_POLICIES[None])

    if sec_res is not None:
        if sec_res.decision == "deny":
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": _gate_reason(
                        "actx security gate violation",
                        sec_res.category, sec_res.reason),
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
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "ask",
                    "permissionDecisionReason": (
                        f"actx security gate confirmation required: {sec_res.reason}"
                    ),
                }
            }

    # 2. Output compression rewrite (for safe/allowed commands)
    try:
        rewritten = rewriter.rewrite(command)
    except Exception:
        rewritten = None

    if rewritten is None:
        # Clean/safe command without compression -> strictly return None
        # to defer to the agent harness's native permission policy
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
    `--agent` or any unknown token -> agent None (today's behaviour).
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
