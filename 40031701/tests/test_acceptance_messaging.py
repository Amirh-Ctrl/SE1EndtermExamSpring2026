from __future__ import annotations

import tempfile
import threading
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from secure_messenger.client.api import MessengerApiClient
from secure_messenger.crypto import IdentityKeyPair, decrypt_message, encrypt_message
from secure_messenger.crypto.e2ee import b64encode
from secure_messenger.server.http_api import create_server
from secure_messenger.server.repository import SQLiteMessengerRepository
from secure_messenger.server.service import MessengerService


class MessagingAcceptanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        database_path = Path(self.temp_dir.name) / "messenger.db"
        self.repository = SQLiteMessengerRepository(database_path)
        self.service = MessengerService(self.repository)
        self.server = create_server("127.0.0.1", 0, self.service)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        self.client = MessengerApiClient(f"http://{host}:{port}")

    def tearDown(self) -> None:
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()
        self.repository.close()
        self.temp_dir.cleanup()

    def test_registered_users_can_exchange_an_e2e_encrypted_message(self) -> None:
        alice_identity = IdentityKeyPair.generate()
        bob_identity = IdentityKeyPair.generate()

        alice_profile = self.client.register_user("alice", "alice-pass-123", b64encode(alice_identity.public_key))
        bob_profile = self.client.register_user("bob", "bob-pass-123", b64encode(bob_identity.public_key))
        self.assertIn("fingerprint", alice_profile)
        self.assertIn("fingerprint", bob_profile)

        envelope = encrypt_message(
            sender="alice",
            recipient="bob",
            plaintext="قرار جلسه ساعت ۱۰",
            sender_identity=alice_identity,
            recipient_public_key=bob_profile["public_key"],
        )
        message_id = self.client.send_message("alice", "alice-pass-123", envelope)
        self.assertGreaterEqual(message_id, 1)

        inbox = self.client.read_inbox("bob", "bob-pass-123")
        self.assertEqual(len(inbox), 1)
        self.assertEqual(inbox[0]["sender"], "alice")
        self.assertEqual(decrypt_message(inbox[0]["envelope"], bob_identity), "قرار جلسه ساعت ۱۰")


if __name__ == "__main__":
    unittest.main()
