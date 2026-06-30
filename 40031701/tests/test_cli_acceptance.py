from __future__ import annotations

import contextlib
import io
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from secure_messenger import cli
from secure_messenger.server.http_api import create_server
from secure_messenger.server.repository import SQLiteMessengerRepository
from secure_messenger.server.service import MessengerService


class CliAcceptanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.profiles_dir = root / "profiles"
        self.repository = SQLiteMessengerRepository(root / "messenger.db")
        self.service = MessengerService(self.repository)
        self.server = create_server("127.0.0.1", 0, self.service)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        self.server_url = f"http://{host}:{port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()
        self.repository.close()
        self.temp_dir.cleanup()

    def test_cli_user_flow_register_send_and_read(self) -> None:
        self.assertEqual(
            self._run_cli(
                "init-user",
                "alice",
                "--password",
                "alice-pass-123",
                "--server-url",
                self.server_url,
                "--profiles-dir",
                str(self.profiles_dir),
            )[0],
            0,
        )
        self.assertEqual(
            self._run_cli(
                "init-user",
                "bob",
                "--password",
                "bob-pass-123",
                "--server-url",
                self.server_url,
                "--profiles-dir",
                str(self.profiles_dir),
            )[0],
            0,
        )
        self.assertEqual(
            self._run_cli(
                "send",
                "alice",
                "bob",
                "--message",
                "پیام از مسیر CLI",
                "--password",
                "alice-pass-123",
                "--server-url",
                self.server_url,
                "--profiles-dir",
                str(self.profiles_dir),
            )[0],
            0,
        )

        exit_code, output = self._run_cli(
            "inbox",
            "bob",
            "--password",
            "bob-pass-123",
            "--server-url",
            self.server_url,
            "--profiles-dir",
            str(self.profiles_dir),
        )
        self.assertEqual(exit_code, 0)
        self.assertIn("پیام از مسیر CLI", output)

    def _run_cli(self, *args: str) -> tuple[int, str]:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            exit_code = cli.main(list(args))
        return exit_code, output.getvalue()


if __name__ == "__main__":
    unittest.main()

