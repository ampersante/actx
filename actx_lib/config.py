import json
import os
import sys

DEFAULT_CONFIG = {
    "tee": {
        "enabled": True,
        "mode": "failures",
        "dir": "~/.local/share/actx/tee",
        "min_bytes": 0,
    },
    "truncate": {
        "max_lines": 500,
        "max_line_chars": 300,
    },
    # Hang-policy timeouts (seconds): default for the general class,
    # generous for known long builders (see actx_lib/hang_policy.py).
    "timeouts": {
        "default_s": 600,
        "generous_s": 1800,
    },
    "bypass_commands": [],
    # User-declared command heads (TK-39): `actx <head> args` behaves like
    # `actx run <head> args`; never extends the §7 rewriter whitelist.
    "custom_heads": [],
    "ignore_dirs": [".git", "node_modules", "target"],
    "ignore_files": ["*.lock"],
    "tracking": {"enabled": True, "history_days": 90},
}


def _config_path():
    return os.path.expanduser("~/.config/actx/config.json")


# Keys whose default is an int but which accept any number (consumed by
# float()); every other int default is strict (slices, counts).
_NUMBER_KEYS = frozenset({"timeouts.default_s", "timeouts.generous_s"})

# Dotted keys already warned about in this process.
_WARNED = set()


def _copy(value):
    return json.loads(json.dumps(value))


def _type_ok(dotted, default, value):
    # bool is checked first: a bool is never a number and vice versa.
    if isinstance(default, bool) or isinstance(value, bool):
        return isinstance(default, bool) and isinstance(value, bool)
    if dotted in _NUMBER_KEYS:
        return isinstance(value, (int, float))
    return isinstance(value, type(default))


def _wrong_type(dotted):
    if dotted not in _WARNED:
        _WARNED.add(dotted)
        print(
            "[actx] config: '%s' has wrong type, using default" % dotted,
            file=sys.stderr,
        )


def _merge(defaults, loaded, prefix=""):
    """defaults overlaid with loaded, recursively; a value whose type
    differs from its default's falls back to the default with one warning
    per process. Keys absent from defaults pass through unchanged."""
    if not isinstance(loaded, dict):
        return _copy(defaults)
    merged = dict(loaded)
    for key, default in defaults.items():
        dotted = prefix + key
        if key not in loaded:
            merged[key] = _copy(default)
        elif isinstance(default, dict):
            if isinstance(loaded[key], dict):
                merged[key] = _merge(default, loaded[key], dotted + ".")
            else:
                _wrong_type(dotted)
                merged[key] = _copy(default)
        elif not _type_ok(dotted, default, loaded[key]):
            _wrong_type(dotted)
            merged[key] = _copy(default)
    return merged


def load():
    path = _config_path()
    if not os.path.exists(path):
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            save(DEFAULT_CONFIG)
        except OSError:
            return json.loads(json.dumps(DEFAULT_CONFIG))
        return json.loads(json.dumps(DEFAULT_CONFIG))
    try:
        with open(path, "r", encoding="utf-8") as handle:
            loaded = json.load(handle)
    except (OSError, ValueError):
        return json.loads(json.dumps(DEFAULT_CONFIG))
    return _merge(DEFAULT_CONFIG, loaded)


def save(config):
    path = _config_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(config, handle, indent=2)
        handle.write("\n")
