import shlex

_FORBIDDEN = set("\n\r\t\0;&&|<>$`(){}#")


def rewrite(command):
    if not command:
        return None
    if command.startswith("actx "):
        return None
    if len(command) > 4096:
        return None
    if any(ch in _FORBIDDEN for ch in command):
        return None
    try:
        tokens = shlex.split(command)
    except ValueError:
        return None
    if not tokens:
        return None

    head = tokens[0]
    if head == "git":
        if (
            len(tokens) >= 2
            and tokens[1] in {"status", "diff", "log"}
            and not any(tok.startswith("--out") for tok in tokens)
        ):
            return "actx " + command
        return None
    if head == "ls":
        if len(tokens) == 1:
            return "actx " + command
        if len(tokens) == 2 and tokens[1] and not tokens[1].startswith("-"):
            return "actx " + command
        return None
    if head == "grep":
        return "actx " + command
    if head == "find":
        forbidden = {
            "-delete", "-exec", "-execdir", "-ok", "-okdir",
            "-fprint", "-fprintf", "-fls",
        }
        if forbidden.isdisjoint(tokens):
            return "actx " + command
        return None
    return None
