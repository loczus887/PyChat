from __future__ import annotations

import sqlite3

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    UNIQUE NOT NULL,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'user',
    created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);
"""


class UserDB:
    def __init__(self, db_path: str = "pychat.db") -> None:
        self._db_path = db_path
        self._conn: sqlite3.Connection | None = None

    def init(self) -> None:
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def create_user(self, username: str, password_hash: str, role: str = "user") -> bool:
        try:
            self._conn.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (username, password_hash, role),
            )
            self._conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def get_password_hash(self, username: str) -> str | None:
        row = self._conn.execute(
            "SELECT password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        return row[0] if row else None

    def get_role(self, username: str) -> str | None:
        row = self._conn.execute(
            "SELECT role FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        return row[0] if row else None

    def user_exists(self, username: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        return row is not None

    def delete_user(self, username: str) -> bool:
        cursor = self._conn.execute(
            "DELETE FROM users WHERE username = ?",
            (username,),
        )
        self._conn.commit()
        return cursor.rowcount > 0
