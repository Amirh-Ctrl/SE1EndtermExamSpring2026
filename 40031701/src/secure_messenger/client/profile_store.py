from __future__ import annotations

import json
import os
from pathlib import Path

from secure_messenger.crypto import IdentityKeyPair


class ProfileStore:
    def __init__(self, directory: str | Path | None = None):
        if directory is not None:
            self.directory = Path(directory)
        else:
            base_directory = os.environ.get("SECURE_MESSENGER_HOME")
            self.directory = Path(base_directory or Path.home() / ".secure_messenger") / "profiles"
        self.directory.mkdir(parents=True, exist_ok=True)

    def save(self, username: str, identity: IdentityKeyPair, server_url: str) -> Path:
        path = self._path(username)
        data = {
            "username": username.lower(),
            "server_url": server_url,
            "identity": identity.to_json_dict(),
        }
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return path

    def load(self, username: str) -> dict:
        path = self._path(username)
        data = json.loads(path.read_text(encoding="utf-8"))
        data["identity"] = IdentityKeyPair.from_json_dict(data["identity"])
        return data

    def _path(self, username: str) -> Path:
        safe_username = username.strip().lower()
        return self.directory / f"{safe_username}.json"
