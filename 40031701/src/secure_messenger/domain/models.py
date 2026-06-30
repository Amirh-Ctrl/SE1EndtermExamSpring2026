from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class UserAccount:
    username: str
    password_salt: str
    password_hash: str
    public_key: str
    created_at: str


@dataclass(frozen=True)
class PublicUserProfile:
    username: str
    public_key: str
    fingerprint: str


@dataclass(frozen=True)
class EncryptedMessage:
    message_id: int
    sender: str
    recipient: str
    envelope: dict
    created_at: str

