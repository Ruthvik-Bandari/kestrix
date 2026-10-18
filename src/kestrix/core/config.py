# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Per-user settings stored on the user's own machine.

API keys are read from the environment first, then from a config file created with
0600 permissions. Keys are never logged, returned by the API, or written to evidence.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

ANTHROPIC_ENV = "ANTHROPIC_API_KEY"


def config_dir() -> Path:
    override = os.environ.get("KESTRIX_HOME")
    if override:
        return Path(override)
    if sys.platform == "win32":
        return Path(os.environ.get("APPDATA", Path.home())) / "kestrix"
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "kestrix"


def _secrets_path() -> Path:
    return config_dir() / "secrets.json"


def _read_secrets() -> dict[str, str]:
    path = _secrets_path()
    try:
        data = json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {k: v for k, v in data.items() if isinstance(k, str) and isinstance(v, str)}


def get_secret(name: str, env_var: str | None = None) -> str | None:
    if env_var and os.environ.get(env_var):
        return os.environ[env_var]
    return _read_secrets().get(name)


def set_secret(name: str, value: str | None) -> None:
    """Store (or with ``None`` remove) a secret in a file only the current user can read."""
    secrets = _read_secrets()
    if value is None:
        secrets.pop(name, None)
    else:
        secrets[name] = value
    path = _secrets_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)  # mkdir does not tighten a directory that already exists
    # mkstemp creates a unique 0600 file with O_EXCL, so it never follows or reuses an existing path.
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".secrets-")
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(secrets, fh)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def anthropic_key() -> str | None:
    return get_secret("anthropic_api_key", ANTHROPIC_ENV)
