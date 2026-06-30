from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone

from . import chacha20poly1305
from .x25519 import generate_private_key, public_key_from_private, x25519

ALGORITHM = "X25519-HKDF-SHA256+ChaCha20-Poly1305"
VERSION = 1


class EncryptionError(ValueError):
    """Raised when an encrypted envelope is invalid or cannot be decrypted."""


def b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def canonical_json(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    if length <= 0:
        raise ValueError("HKDF length must be positive.")

    pseudo_random_key = hmac.new(salt or b"\x00" * 32, ikm, hashlib.sha256).digest()
    output = bytearray()
    block = b""
    counter = 1
    while len(output) < length:
        block = hmac.new(pseudo_random_key, block + info + bytes([counter]), hashlib.sha256).digest()
        output.extend(block)
        counter += 1
    return bytes(output[:length])


@dataclass(frozen=True)
class IdentityKeyPair:
    private_key: bytes
    public_key: bytes

    @classmethod
    def generate(cls) -> "IdentityKeyPair":
        private_key = generate_private_key()
        return cls(private_key=private_key, public_key=public_key_from_private(private_key))

    def to_json_dict(self) -> dict:
        return {
            "private_key": b64encode(self.private_key),
            "public_key": b64encode(self.public_key),
            "fingerprint": fingerprint(self.public_key),
        }

    @classmethod
    def from_json_dict(cls, data: dict) -> "IdentityKeyPair":
        private_key = b64decode(data["private_key"])
        public_key = public_key_from_private(private_key)
        saved_public_key = b64decode(data["public_key"])
        if public_key != saved_public_key:
            raise EncryptionError("Saved identity key pair is inconsistent.")
        return cls(private_key=private_key, public_key=public_key)


def fingerprint(public_key: bytes | str) -> str:
    if isinstance(public_key, str):
        public_key = b64decode(public_key)
    digest = hashlib.sha256(public_key).hexdigest().upper()
    return ":".join(digest[index : index + 4] for index in range(0, 32, 4))


def _derive_message_key(shared_secret: bytes, header: dict) -> bytes:
    aad = canonical_json(header)
    salt = hashlib.sha256(b"secure-messenger-salt-v1" + aad).digest()
    return hkdf_sha256(
        ikm=shared_secret,
        salt=salt,
        info=b"secure-messenger/e2ee/message-key/v1",
        length=32,
    )


def _header_from_envelope(envelope: dict) -> dict:
    header_keys = (
        "version",
        "algorithm",
        "sender",
        "recipient",
        "sent_at",
        "sender_identity_key",
        "sender_ephemeral_key",
        "nonce",
    )
    try:
        return {key: envelope[key] for key in header_keys}
    except KeyError as exc:
        raise EncryptionError(f"Encrypted envelope misses field: {exc.args[0]}") from exc


def encrypt_message(
    sender: str,
    recipient: str,
    plaintext: str,
    sender_identity: IdentityKeyPair,
    recipient_public_key: bytes | str,
    sent_at: datetime | None = None,
) -> dict:
    if not sender or not recipient:
        raise EncryptionError("Sender and recipient are required.")
    if isinstance(recipient_public_key, str):
        recipient_public_key = b64decode(recipient_public_key)

    sent_at = sent_at or datetime.now(timezone.utc)
    ephemeral_private_key = generate_private_key()
    ephemeral_public_key = public_key_from_private(ephemeral_private_key)
    nonce = secrets.token_bytes(12)

    header = {
        "version": VERSION,
        "algorithm": ALGORITHM,
        "sender": sender,
        "recipient": recipient,
        "sent_at": sent_at.isoformat(),
        "sender_identity_key": b64encode(sender_identity.public_key),
        "sender_ephemeral_key": b64encode(ephemeral_public_key),
        "nonce": b64encode(nonce),
    }

    ephemeral_secret = x25519(ephemeral_private_key, recipient_public_key)
    sender_auth_secret = x25519(sender_identity.private_key, recipient_public_key)
    message_key = _derive_message_key(ephemeral_secret + sender_auth_secret, header)
    aad = canonical_json(header)
    ciphertext, tag = chacha20poly1305.encrypt(message_key, nonce, plaintext.encode("utf-8"), aad)

    return {
        **header,
        "ciphertext": b64encode(ciphertext),
        "tag": b64encode(tag),
    }


def decrypt_message(envelope: dict, recipient_identity: IdentityKeyPair) -> str:
    header = _header_from_envelope(envelope)
    if header["version"] != VERSION:
        raise EncryptionError("Unsupported encrypted envelope version.")
    if header["algorithm"] != ALGORITHM:
        raise EncryptionError("Unsupported encrypted envelope algorithm.")

    try:
        sender_identity_public_key = b64decode(header["sender_identity_key"])
        sender_ephemeral_public_key = b64decode(header["sender_ephemeral_key"])
        nonce = b64decode(header["nonce"])
        ciphertext = b64decode(envelope["ciphertext"])
        tag = b64decode(envelope["tag"])
    except (KeyError, ValueError) as exc:
        raise EncryptionError("Encrypted envelope has invalid binary fields.") from exc

    ephemeral_secret = x25519(recipient_identity.private_key, sender_ephemeral_public_key)
    sender_auth_secret = x25519(recipient_identity.private_key, sender_identity_public_key)
    message_key = _derive_message_key(ephemeral_secret + sender_auth_secret, header)
    aad = canonical_json(header)

    try:
        plaintext = chacha20poly1305.decrypt(message_key, nonce, ciphertext, tag, aad)
    except chacha20poly1305.AuthenticationFailed as exc:
        raise EncryptionError("Encrypted message authentication failed.") from exc
    return plaintext.decode("utf-8")

