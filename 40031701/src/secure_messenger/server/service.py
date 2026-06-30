from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
from datetime import datetime, timezone

from secure_messenger.crypto import fingerprint
from secure_messenger.crypto.e2ee import b64decode
from secure_messenger.domain.exceptions import AuthenticationError, NotFoundError, ValidationError
from secure_messenger.domain.models import EncryptedMessage, PublicUserProfile, UserAccount
from secure_messenger.server.repository import SQLiteMessengerRepository

USERNAME_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]{2,31}$")
PASSWORD_ITERATIONS = 200_000


class MessengerService:
    def __init__(self, repository: SQLiteMessengerRepository):
        self.repository = repository

    def register_user(self, username: str, password: str, public_key: str) -> PublicUserProfile:
        username = self._normalize_username(username)
        self._validate_password(password)
        self._validate_public_key(public_key)
        if self.repository.get_user(username) is not None:
            raise ValidationError("Username already exists.")

        salt = secrets.token_bytes(16)
        account = UserAccount(
            username=username,
            password_salt=base64.b64encode(salt).decode("ascii"),
            password_hash=self._hash_password(password, salt),
            public_key=public_key,
            created_at=self._now(),
        )
        self.repository.add_user(account)
        return self._public_profile(account)

    def get_public_profile(self, username: str) -> PublicUserProfile:
        account = self.repository.get_user(self._normalize_username(username))
        if account is None:
            raise NotFoundError("User does not exist.")
        return self._public_profile(account)

    def send_message(self, username: str, password: str, envelope: dict) -> int:
        sender = self._authenticate(username, password)
        self._validate_envelope(sender, envelope)
        recipient = self.repository.get_user(self._normalize_username(envelope["recipient"]))
        if recipient is None:
            raise NotFoundError("Recipient does not exist.")
        return self.repository.save_message(sender.username, recipient.username, envelope, self._now())

    def read_inbox(self, username: str, password: str, after_id: int = 0) -> list[EncryptedMessage]:
        account = self._authenticate(username, password)
        return self.repository.list_inbox(account.username, after_id=max(0, int(after_id)))

    def _authenticate(self, username: str, password: str) -> UserAccount:
        account = self.repository.get_user(self._normalize_username(username))
        if account is None:
            raise AuthenticationError("Invalid username or password.")
        salt = base64.b64decode(account.password_salt)
        expected_hash = self._hash_password(password, salt)
        if not hmac.compare_digest(expected_hash, account.password_hash):
            raise AuthenticationError("Invalid username or password.")
        return account

    def _validate_envelope(self, sender: UserAccount, envelope: dict) -> None:
        required_fields = {
            "version",
            "algorithm",
            "sender",
            "recipient",
            "sent_at",
            "sender_identity_key",
            "sender_ephemeral_key",
            "nonce",
            "ciphertext",
            "tag",
        }
        missing = required_fields - set(envelope)
        if missing:
            raise ValidationError(f"Envelope misses fields: {', '.join(sorted(missing))}.")
        if self._normalize_username(envelope["sender"]) != sender.username:
            raise ValidationError("Envelope sender does not match authenticated user.")
        if envelope["sender_identity_key"] != sender.public_key:
            raise ValidationError("Envelope sender identity key does not match registered key.")
        self._normalize_username(envelope["recipient"])

    def _public_profile(self, account: UserAccount) -> PublicUserProfile:
        return PublicUserProfile(
            username=account.username,
            public_key=account.public_key,
            fingerprint=fingerprint(account.public_key),
        )

    @staticmethod
    def _normalize_username(username: str) -> str:
        username = (username or "").strip().lower()
        if not USERNAME_PATTERN.match(username):
            raise ValidationError("Username must be 3-32 chars and start with a letter.")
        return username

    @staticmethod
    def _validate_password(password: str) -> None:
        if len(password or "") < 8:
            raise ValidationError("Password must be at least 8 characters.")

    @staticmethod
    def _validate_public_key(public_key: str) -> None:
        try:
            decoded = b64decode(public_key)
        except ValueError as exc:
            raise ValidationError("Public key must be base64url encoded.") from exc
        if len(decoded) != 32:
            raise ValidationError("Public key must be a 32-byte X25519 key.")

    @staticmethod
    def _hash_password(password: str, salt: bytes) -> str:
        digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            PASSWORD_ITERATIONS,
        )
        return base64.b64encode(digest).decode("ascii")

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

