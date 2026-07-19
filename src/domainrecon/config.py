from __future__ import annotations

import json
import os
from pathlib import Path

ENV_PATH = Path(".env")
ALLOWED_SECRETS = {"SHODAN_API_KEY", "CENSYS_PAT"}


def load_env(path: Path = ENV_PATH) -> None:
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip()
        if key not in ALLOWED_SECRETS:
            continue
        if value.startswith('"'):
            try:
                value = json.loads(value)
            except json.JSONDecodeError:
                continue
        os.environ.setdefault(key, value)


def save_secrets(values: dict[str, str | None], path: Path = ENV_PATH) -> None:
    current: dict[str, str] = {}
    if path.is_file():
        for raw in path.read_text(encoding="utf-8").splitlines():
            if "=" in raw and not raw.lstrip().startswith("#"):
                key, value = raw.split("=", 1)
                current[key.strip()] = value.strip()
    for key, value in values.items():
        if key not in ALLOWED_SECRETS or value is None:
            continue
        if "\n" in value or "\r" in value or len(value) > 1000:
            raise ValueError(f"invalid value for {key}")
        if value:
            current[key] = json.dumps(value)
            os.environ[key] = value
        else:
            current.pop(key, None)
            os.environ.pop(key, None)
    content = "# Managed locally by DomainRecon. Never commit this file.\n"
    content += "\n".join(f"{key}={current[key]}" for key in sorted(current))
    content += "\n"
    path.write_text(content, encoding="utf-8")
    path.chmod(0o600)


load_env()
