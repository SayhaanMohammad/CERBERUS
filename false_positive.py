import fnmatch
import json
import os


DEFAULT_CONFIG = {
    "monitor_directory": "test_files",
    "window_seconds": 10,
    "file_threshold": 20,
    "ignore_patterns": [],
    "expected_activity_patterns": []
}


def load_config(config_path="config.json"):
    if not os.path.exists(config_path):
        save_config(DEFAULT_CONFIG, config_path)
    try:
        with open(config_path, "r", encoding="utf-8") as file:
            config = json.load(file)
    except (OSError, json.JSONDecodeError):
        config = DEFAULT_CONFIG.copy()
    for key, value in DEFAULT_CONFIG.items():
        config.setdefault(key, value)
    return config


def save_config(config, config_path="config.json"):
    with open(config_path, "w", encoding="utf-8") as file:
        json.dump(config, file, indent=2)


def check_false_positive(event, config):
    """
    Return (is_expected, explanation).
    Patterns match paths relative to the monitored folder or full paths.
    Use narrowly scoped patterns; an ignored path is not proof that activity is safe.
    """
    paths = [event.get("src_path", ""), event.get("dest_path", "")]
    patterns = config.get("ignore_patterns", [])
    for path in paths:
        if not path:
            continue
        for pattern in patterns:
            if fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch(os.path.basename(path), pattern):
                return True, f"Path matches configured ignore pattern: {pattern}"

    expected_patterns = config.get("expected_activity_patterns", [])
    for path in paths:
        if not path:
            continue
        for pattern in expected_patterns:
            if fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch(os.path.basename(path), pattern):
                return True, f"Path matches expected activity pattern: {pattern}"

    return False, ""
