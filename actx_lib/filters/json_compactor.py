"""Reusable JSON-output compactor for infra/data CLI filters.

Valid JSON -> redact secret keys (redaction.redact_json) -> optionally trim
long lists head/tail with a count marker -> json.dumps. Invalid JSON or any
internal error -> None, so the caller keeps its line-based path (fail-open).
Pure: no I/O.
"""

import json

from actx_lib import redaction


def _trim_lists(obj, max_items):
    if isinstance(obj, dict):
        return {key: _trim_lists(value, max_items) for key, value in obj.items()}
    if isinstance(obj, list):
        if len(obj) > max_items:
            keep = max_items // 2
            omitted = len(obj) - max_items
            head = [_trim_lists(value, max_items) for value in obj[:keep]]
            tail = [_trim_lists(value, max_items) for value in obj[-keep:]]
            return head + ["... [%d items omitted]" % omitted] + tail
        return [_trim_lists(value, max_items) for value in obj]
    return obj


def compact_json(text, *, indent=None, sort_keys=False, max_items=20):
    """Valid JSON -> compact dump with secrets masked; None when invalid."""
    try:
        obj = json.loads(text.strip())
        obj = redaction.redact_json(obj)
        if max_items is not None:
            obj = _trim_lists(obj, max_items)
        return json.dumps(obj, indent=indent, sort_keys=sort_keys)
    except Exception:
        return None
