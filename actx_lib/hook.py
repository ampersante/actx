import json
import sys

import actx_lib.rewriter as rewriter

ALLOWED_TOOLS = {"Bash", "bash", "Shell"}

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

    tool_name = data.get("tool_name")
    if tool_name not in ALLOWED_TOOLS:
        print("actx hook: missing or unsupported tool_name", file=sys.stderr)
        return None

    tool_input = data.get("tool_input")
    if not isinstance(tool_input, dict):
        print("actx hook: tool_input is not an object", file=sys.stderr)
        return None

    command = tool_input.get("command")
    if not isinstance(command, str):
        print("actx hook: command is missing or not a string", file=sys.stderr)
        return None

    rewritten = rewriter.rewrite(command)
    if rewritten is None:
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
