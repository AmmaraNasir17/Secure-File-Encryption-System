import sqlite3
from contextlib import contextmanager
from pathlib import Path

from utils import DB_PATH, iso_timestamp


class DatabaseManager:
    def __init__(self, db_path=DB_PATH):
        self.db_path = Path(db_path)
        self.init_db()

    @contextmanager
    def connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def init_db(self):
        with self.connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    failed_attempts INTEGER DEFAULT 0,
                    locked_until TEXT,
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    action TEXT NOT NULL,
                    filename TEXT,
                    timestamp TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS integrity (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    encrypted_filename TEXT UNIQUE NOT NULL,
                    hash_value TEXT NOT NULL,
                    signature_path TEXT,
                    timestamp TEXT NOT NULL
                )
                """
            )
            conn.commit()

    def create_user(self, username, password_hash):
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO users (username, password_hash, failed_attempts, locked_until, created_at)
                VALUES (?, ?, 0, NULL, ?)
                """,
                (username, password_hash, iso_timestamp()),
            )
            conn.commit()

    def get_user(self, username):
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            return dict(row) if row else None

    def reset_failed_attempts(self, username):
        with self.connect() as conn:
            conn.execute(
                "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE username = ?",
                (username,),
            )
            conn.commit()

    def increment_failed_attempts(self, username):
        with self.connect() as conn:
            conn.execute(
                "UPDATE users SET failed_attempts = failed_attempts + 1 WHERE username = ?",
                (username,),
            )
            row = conn.execute(
                "SELECT failed_attempts FROM users WHERE username = ?",
                (username,),
            ).fetchone()
            conn.commit()
            return int(row["failed_attempts"]) if row else 0

    def lock_user(self, username, lock_time):
        with self.connect() as conn:
            conn.execute(
                "UPDATE users SET locked_until = ? WHERE username = ?",
                (lock_time, username),
            )
            conn.commit()

    def add_log(self, username, action, filename=""):
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO logs (username, action, filename, timestamp)
                VALUES (?, ?, ?, ?)
                """,
                (username, action, filename, iso_timestamp()),
            )
            conn.commit()

    def get_logs(self, limit=300):
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT id, username, action, filename, timestamp
                FROM logs
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            return [dict(row) for row in rows]

    def add_integrity_record(self, username, filename, enc_filename, hash_val, sig_path=""):
        with self.connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO integrity
                    (username, filename, encrypted_filename, hash_value, signature_path, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    username,
                    str(Path(filename).resolve()),
                    str(Path(enc_filename).resolve()),
                    hash_val,
                    sig_path,
                    iso_timestamp(),
                ),
            )
            conn.commit()

    def get_integrity_by_encrypted_file(self, enc_filename):
        path = str(Path(enc_filename).resolve())
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM integrity
                WHERE encrypted_filename = ? OR encrypted_filename LIKE ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (path, f"%{Path(enc_filename).name}"),
            ).fetchone()
            return dict(row) if row else None

    def get_integrity_by_original_file(self, filename):
        path = str(Path(filename).resolve())
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM integrity
                WHERE filename = ? OR filename LIKE ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (path, f"%{Path(filename).name}"),
            ).fetchone()
            return dict(row) if row else None

    def count_rows(self, table):
        if table not in {"users", "logs", "integrity"}:
            raise ValueError("Bad table name")
        with self.connect() as conn:
            row = conn.execute(f"SELECT COUNT(*) AS total FROM {table}").fetchone()
            return int(row["total"])
