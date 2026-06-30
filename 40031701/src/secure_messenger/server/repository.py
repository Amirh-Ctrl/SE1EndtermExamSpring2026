from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path

from secure_messenger.domain.models import EncryptedMessage, UserAccount


class SQLiteMessengerRepository:
    def __init__(self, database_path: str | Path):
        self.database_path = str(database_path)
        Path(self.database_path).parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(self.database_path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self._initialize_schema()

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def _initialize_schema(self) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password_salt TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender TEXT NOT NULL,
                    recipient TEXT NOT NULL,
                    envelope_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(sender) REFERENCES users(username),
                    FOREIGN KEY(recipient) REFERENCES users(username)
                )
                """
            )
            self._connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_messages_recipient_id ON messages(recipient, id)"
            )

    def add_user(self, account: UserAccount) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO users(username, password_salt, password_hash, public_key, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    account.username,
                    account.password_salt,
                    account.password_hash,
                    account.public_key,
                    account.created_at,
                ),
            )

    def get_user(self, username: str) -> UserAccount | None:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT username, password_salt, password_hash, public_key, created_at
                FROM users
                WHERE username = ?
                """,
                (username,),
            ).fetchone()
        if row is None:
            return None
        return UserAccount(
            username=row["username"],
            password_salt=row["password_salt"],
            password_hash=row["password_hash"],
            public_key=row["public_key"],
            created_at=row["created_at"],
        )

    def save_message(self, sender: str, recipient: str, envelope: dict, created_at: str) -> int:
        with self._lock, self._connection:
            cursor = self._connection.execute(
                """
                INSERT INTO messages(sender, recipient, envelope_json, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (sender, recipient, json.dumps(envelope, sort_keys=True), created_at),
            )
            return int(cursor.lastrowid)

    def list_inbox(self, recipient: str, after_id: int = 0) -> list[EncryptedMessage]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT id, sender, recipient, envelope_json, created_at
                FROM messages
                WHERE recipient = ? AND id > ?
                ORDER BY id ASC
                """,
                (recipient, after_id),
            ).fetchall()

        return [
            EncryptedMessage(
                message_id=int(row["id"]),
                sender=row["sender"],
                recipient=row["recipient"],
                envelope=json.loads(row["envelope_json"]),
                created_at=row["created_at"],
            )
            for row in rows
        ]

