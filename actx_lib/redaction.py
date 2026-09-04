"""Single source of truth for secret patterns and redaction helpers."""

import json

_SECRET_PATTERNS = (
    "secret",
    "token",
    "password",
    "accesskey",
    "credential",
    "aws_access_key_id",
    "aws_secret_access_key",
    "api_key",
    "apikey",
    "private_key",
    "secret_key",
    "client_secret",
    "access_key",
    "signing_key",
    "passphrase",
)


def _is_secret_key(key):
    lowered = key.lower()
    return any(pattern in lowered for pattern in _SECRET_PATTERNS)


def _drop_secret_lines(text):
    return "\n".join(
        line for line in text.split("\n") if not any(p in line.lower() for p in _SECRET_PATTERNS)
    )


def _drop_secret_json(obj):
    if isinstance(obj, dict):
        return {
            key: _drop_secret_json(value)
            for key, value in obj.items()
            if not _is_secret_key(key)
        }
    if isinstance(obj, list):
        return [_drop_secret_json(value) for value in obj]
    return obj


def redact_text(text):
    """Drop secret-bearing lines. Fail-open: on internal error return the
    input unchanged (callers also own a fail-open path around redaction)."""
    if not text:
        return text
    try:
        return _drop_secret_lines(text)
    except Exception:
        return text


def redact_json(obj):
    """Recursively drop dict keys that look like secrets."""
    return _drop_secret_json(obj)


def secret_bearing(text):
    """True when text looks like it contains secrets. Line-level heuristic:
    any line matching a secret pattern is enough. Fail-open to True — when
    detection fails, treat output as secret-bearing."""
    if not text:
        return False
    try:
        return any(p in line.lower() for line in text.split("\n") for p in _SECRET_PATTERNS)
    except Exception:
        return True
