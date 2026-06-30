from __future__ import annotations

import argparse
import getpass
import json
from pathlib import Path

from secure_messenger.client.api import ApiClientError, MessengerApiClient
from secure_messenger.client.profile_store import ProfileStore
from secure_messenger.crypto import IdentityKeyPair, decrypt_message, encrypt_message, fingerprint
from secure_messenger.crypto.e2ee import b64encode
from secure_messenger.server.http_api import run_server

DEFAULT_SERVER_URL = "http://127.0.0.1:8080"


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except (ApiClientError, FileNotFoundError, KeyError, ValueError) as exc:
        print(f"Error: {exc}")
        return 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="secure-messenger")
    subparsers = parser.add_subparsers(required=True)

    server = subparsers.add_parser("server", help="Start the HTTP message broker.")
    server.add_argument("--host", default="127.0.0.1")
    server.add_argument("--port", type=int, default=8080)
    server.add_argument("--db", default="data/messenger.db")
    server.set_defaults(handler=_handle_server)

    init_user = subparsers.add_parser("init-user", help="Create a local identity and register it.")
    init_user.add_argument("username")
    init_user.add_argument("--password")
    init_user.add_argument("--server-url", default=DEFAULT_SERVER_URL)
    init_user.add_argument("--profiles-dir")
    init_user.set_defaults(handler=_handle_init_user)

    send = subparsers.add_parser("send", help="Encrypt and send a message.")
    send.add_argument("sender")
    send.add_argument("recipient")
    send.add_argument("--message", required=True)
    send.add_argument("--password")
    send.add_argument("--server-url", default=DEFAULT_SERVER_URL)
    send.add_argument("--profiles-dir")
    send.set_defaults(handler=_handle_send)

    inbox = subparsers.add_parser("inbox", help="Read and decrypt new messages.")
    inbox.add_argument("username")
    inbox.add_argument("--password")
    inbox.add_argument("--server-url", default=DEFAULT_SERVER_URL)
    inbox.add_argument("--profiles-dir")
    inbox.add_argument("--after-id", type=int, default=0)
    inbox.set_defaults(handler=_handle_inbox)

    profile = subparsers.add_parser("fingerprint", help="Show the local identity fingerprint.")
    profile.add_argument("username")
    profile.add_argument("--profiles-dir")
    profile.set_defaults(handler=_handle_fingerprint)

    return parser


def _handle_server(args: argparse.Namespace) -> int:
    run_server(args.host, args.port, Path(args.db))
    return 0


def _handle_init_user(args: argparse.Namespace) -> int:
    password = _password(args.password)
    identity = IdentityKeyPair.generate()
    client = MessengerApiClient(args.server_url)
    public_key = b64encode(identity.public_key)
    user = client.register_user(args.username, password, public_key)
    saved_path = ProfileStore(args.profiles_dir).save(args.username, identity, args.server_url)
    print(f"registered={user['username']}")
    print(f"fingerprint={user['fingerprint']}")
    print(f"profile={saved_path}")
    return 0


def _handle_send(args: argparse.Namespace) -> int:
    password = _password(args.password)
    store = ProfileStore(args.profiles_dir)
    sender_profile = store.load(args.sender)
    client = MessengerApiClient(args.server_url)
    recipient = client.get_public_profile(args.recipient)
    envelope = encrypt_message(
        sender=args.sender,
        recipient=args.recipient,
        plaintext=args.message,
        sender_identity=sender_profile["identity"],
        recipient_public_key=recipient["public_key"],
    )
    message_id = client.send_message(args.sender, password, envelope)
    print(f"message_id={message_id}")
    print(f"recipient_fingerprint={recipient['fingerprint']}")
    return 0


def _handle_inbox(args: argparse.Namespace) -> int:
    password = _password(args.password)
    store = ProfileStore(args.profiles_dir)
    profile = store.load(args.username)
    client = MessengerApiClient(args.server_url)
    messages = client.read_inbox(args.username, password, after_id=args.after_id)
    for message in messages:
        plaintext = decrypt_message(message["envelope"], profile["identity"])
        print(
            json.dumps(
                {
                    "message_id": message["message_id"],
                    "from": message["sender"],
                    "created_at": message["created_at"],
                    "text": plaintext,
                },
                ensure_ascii=False,
            )
        )
    if not messages:
        print("inbox=empty")
    return 0


def _handle_fingerprint(args: argparse.Namespace) -> int:
    profile = ProfileStore(args.profiles_dir).load(args.username)
    print(fingerprint(profile["identity"].public_key))
    return 0


def _password(value: str | None) -> str:
    return value if value is not None else getpass.getpass("Password: ")

