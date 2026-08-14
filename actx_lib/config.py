import json
import os

DEFAULT_CONFIG = {
    "tee": {
        "enabled": True,
        "mode": "failures",
        "dir": "~/.local/share/actx/tee",
    },
    "truncate": {
        "max_lines": 500,
        "max_line_chars": 300,
    },
}


def _config_path():
    return os.path.expanduser("~/.config/actx/config.json")


def _merge(defaults, loaded):
    if not isinstance(loaded, dict):
        return defaults
    merged = {}
    for key, value in defaults.items():
        loaded_value = loaded.get(key)
        if isinstance(value, dict) and isinstance(loaded_value, dict):
            merged[key] = dict(value)
            merged[key].update(loaded_value)
        elif key in loaded:
            merged[key] = loaded_value
        else:
            merged[key] = value
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
