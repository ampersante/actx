import json
import sys

import actx_lib.rewriter as rewriter
import actx_lib.security_gate as security_gate

ALLOWED_TOOLS = {"Bash", "bash", "Shell", "shell", "exec"}

ADDITIONAL_CONTEXT = "Command rewritten by actx for output compression."


def process(text):
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
                    "decision": "ask",
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
        return {"decision": "allow"}

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

    if sec_res is not None:
        if sec_res.decision == "deny":
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": (
                        f"actx security gate violation [{sec_res.category}]: {sec_res.reason}"
                        if sec_res.category
                        else f"actx security gate violation: {sec_res.reason}"
                    ),
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

    updated_input = dict(tool_input)
    updated_input["command"] = rewritten

    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
            "updatedInput": updated_input,
            "additionalContext": ADDITIONAL_CONTEXT,
        }
    }


def main():
    try:
        text = sys.stdin.read()
    except OSError:
        print("actx hook: failed to read stdin", file=sys.stderr)
        return 1
    result = process(text)
    if result is not None:
        try:
            json.dump(result, sys.stdout)
            sys.stdout.write("\n")
        except (OSError, ValueError):
            print("actx hook: failed to write response", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
