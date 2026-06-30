from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from secure_messenger.domain.exceptions import AuthenticationError, DomainError, NotFoundError, ValidationError
from secure_messenger.server.repository import SQLiteMessengerRepository
from secure_messenger.server.service import MessengerService


class _JsonHandler(BaseHTTPRequestHandler):
    service: MessengerService
    server_version = "SecureMessengerHTTP/1.0"

    def do_GET(self) -> None:
        if self.path == "/health":
            self._send_json(HTTPStatus.OK, {"status": "ok"})
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not found."})

    def do_POST(self) -> None:
        try:
            payload = self._read_json()
            response = self._dispatch(payload)
            self._send_json(HTTPStatus.OK, response)
        except AuthenticationError as exc:
            self._send_json(HTTPStatus.UNAUTHORIZED, {"error": str(exc)})
        except NotFoundError as exc:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": str(exc)})
        except ValidationError as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
        except DomainError as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
        except json.JSONDecodeError:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Request body must be valid JSON."})

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _dispatch(self, payload: dict) -> dict:
        if self.path == "/register":
            profile = self.service.register_user(payload["username"], payload["password"], payload["public_key"])
            return {"user": profile.__dict__}
        if self.path == "/public-key":
            profile = self.service.get_public_profile(payload["username"])
            return {"user": profile.__dict__}
        if self.path == "/send":
            message_id = self.service.send_message(payload["username"], payload["password"], payload["envelope"])
            return {"message_id": message_id}
        if self.path == "/inbox":
            messages = self.service.read_inbox(
                payload["username"],
                payload["password"],
                after_id=int(payload.get("after_id", 0)),
            )
            return {"messages": [message.__dict__ for message in messages]}
        raise ValidationError("Unknown endpoint.")

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        data = json.loads(body.decode("utf-8") if body else "{}")
        if not isinstance(data, dict):
            raise ValidationError("Request body must be a JSON object.")
        return data

    def _send_json(self, status: HTTPStatus, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def create_server(host: str, port: int, service: MessengerService) -> ThreadingHTTPServer:
    handler_class = type("SecureMessengerJsonHandler", (_JsonHandler,), {"service": service})
    return ThreadingHTTPServer((host, port), handler_class)


def run_server(host: str, port: int, database_path: str | Path) -> None:
    repository = SQLiteMessengerRepository(database_path)
    service = MessengerService(repository)
    server = create_server(host, port, service)
    try:
        print(f"Secure Messenger server listening on http://{host}:{port}")
        server.serve_forever()
    finally:
        server.server_close()
        repository.close()

