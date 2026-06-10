from __future__ import annotations

import json
from pathlib import Path
from typing import Any


DEFAULT_CONFIG_PATH = Path("vulnscanner.json")
COMMAND_NAMES = {"scan", "headers", "paths", "history", "diff"}


def load_config(path: str | None) -> tuple[dict[str, Any], Path | None]:
    if path:
        config_path = Path(path)
    elif DEFAULT_CONFIG_PATH.exists():
        config_path = DEFAULT_CONFIG_PATH
    else:
        return {}, None

    data = json.loads(config_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Config file must contain a JSON object.")
    return data, config_path


def resolve_command_defaults(config: dict[str, Any], command: str | None) -> dict[str, Any]:
    shared = config.get("shared", {})
    if shared and not isinstance(shared, dict):
        raise ValueError("The shared config section must be an object.")

    resolved: dict[str, Any] = dict(shared or {})
    if command and command in COMMAND_NAMES:
        command_data = config.get(command, {})
        if command_data and not isinstance(command_data, dict):
            raise ValueError(f"The {command} config section must be an object.")
        resolved.update(command_data or {})
    return resolved
