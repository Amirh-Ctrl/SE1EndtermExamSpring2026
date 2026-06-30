from __future__ import annotations

import base64
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from secure_messenger.crypto import EncryptionError, IdentityKeyPair, decrypt_message, encrypt_message


class EndToEndEncryptionTests(unittest.TestCase):
    def test_message_round_trip_hides_plaintext(self) -> None:
        alice = IdentityKeyPair.generate()
        bob = IdentityKeyPair.generate()

        envelope = encrypt_message("alice", "bob", "سلام باب، پیام محرمانه است.", alice, bob.public_key)

        self.assertNotIn("پیام محرمانه", json.dumps(envelope, ensure_ascii=False))
        self.assertEqual(decrypt_message(envelope, bob), "سلام باب، پیام محرمانه است.")

    def test_tampered_ciphertext_is_rejected(self) -> None:
        alice = IdentityKeyPair.generate()
        bob = IdentityKeyPair.generate()
        envelope = encrypt_message("alice", "bob", "do not change me", alice, bob.public_key)

        tampered = dict(envelope)
        ciphertext = bytearray(_decode(tampered["ciphertext"]))
        ciphertext[0] ^= 1
        tampered["ciphertext"] = _encode(bytes(ciphertext))

        with self.assertRaises(EncryptionError):
            decrypt_message(tampered, bob)

    def test_wrong_recipient_key_cannot_decrypt(self) -> None:
        alice = IdentityKeyPair.generate()
        bob = IdentityKeyPair.generate()
        mallory = IdentityKeyPair.generate()
        envelope = encrypt_message("alice", "bob", "only bob can read this", alice, bob.public_key)

        with self.assertRaises(EncryptionError):
            decrypt_message(envelope, mallory)


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


if __name__ == "__main__":
    unittest.main()
