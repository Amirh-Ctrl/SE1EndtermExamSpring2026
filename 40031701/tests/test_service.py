from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from secure_messenger.crypto import IdentityKeyPair, encrypt_message
from secure_messenger.crypto.e2ee import b64encode
from secure_messenger.domain.exceptions import AuthenticationError, ValidationError
from secure_messenger.server.repository import SQLiteMessengerRepository
from secure_messenger.server.service import MessengerService


class MessengerServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.repository = SQLiteMessengerRepository(Path(self.temp_dir.name) / "messenger.db")
        self.service = MessengerService(self.repository)

    def tearDown(self) -> None:
        self.repository.close()
        self.temp_dir.cleanup()

    def test_duplicate_username_is_rejected(self) -> None:
        alice = IdentityKeyPair.generate()
        self.service.register_user("alice", "alice-pass-123", b64encode(alice.public_key))

        with self.assertRaises(ValidationError):
            self.service.register_user("alice", "another-pass-123", b64encode(alice.public_key))

    def test_wrong_password_cannot_read_inbox(self) -> None:
        alice = IdentityKeyPair.generate()
        self.service.register_user("alice", "alice-pass-123", b64encode(alice.public_key))

        with self.assertRaises(AuthenticationError):
            self.service.read_inbox("alice", "wrong-password")

    def test_sender_identity_mismatch_is_rejected(self) -> None:
        alice = IdentityKeyPair.generate()
        bob = IdentityKeyPair.generate()
        attacker = IdentityKeyPair.generate()
        self.service.register_user("alice", "alice-pass-123", b64encode(alice.public_key))
        self.service.register_user("bob", "bob-pass-123", b64encode(bob.public_key))
        envelope = encrypt_message("alice", "bob", "fake identity", attacker, bob.public_key)

        with self.assertRaises(ValidationError):
            self.service.send_message("alice", "alice-pass-123", envelope)


if __name__ == "__main__":
    unittest.main()

