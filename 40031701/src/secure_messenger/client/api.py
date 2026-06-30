from __future__ import annotations

import json
from urllib import error, request


class ApiClientError(RuntimeError):
    pass


class MessengerApiClient:
    def __init__(self, server_url: str):
        self.server_url = server_url.rstrip("/")

    def register_user(self, username: str, password: str, public_key: str) -> dict:
        return self._post("/register", {"username": username, "password": password, "public_key": public_key})["user"]

    def get_public_profile(self, username: str) -> dict:
        return self._post("/public-key", {"username": username})["user"]

    def send_message(self, username: str, password: str, envelope: dict) -> int:
        response = self._post("/send", {"username": username, "password": password, "envelope": envelope})
        return int(response["message_id"])

    def read_inbox(self, username: str, password: str, after_id: int = 0) -> list[dict]:
        response = self._post("/inbox", {"username": username, "password": password, "after_id": after_id})
        return list(response["messages"])

    def _post(self, path: str, payload: dict) -> dict:
        body = json.dumps(payload).encode("utf-8")
        http_request = request.Request(
            self.server_url + path,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with request.urlopen(http_request, timeout=10) as response:
                return json.loads(response.read().decode("utf-8"))
        except error.HTTPError as exc:
            error_payload = json.loads(exc.read().decode("utf-8"))
            raise ApiClientError(error_payload.get("error", str(exc))) from exc
        except error.URLError as exc:
            raise ApiClientError(f"Cannot connect to server: {exc.reason}") from exc

