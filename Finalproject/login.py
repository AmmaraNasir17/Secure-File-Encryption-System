from datetime import datetime, timedelta
from sqlite3 import IntegrityError

from database import DatabaseManager
from hashing import hash_password_sha256, verify_password_sha256
from logs import SecurityAuditLogger


MAX_FAILED_ATTEMPTS = 5
LOCK_MINUTES = 2


class LoginManager:
    def __init__(self, database, audit_logger):
        self.database = database
        self.audit_logger = audit_logger

    def register_user(self, username, password):
        username = username.strip()
        if len(username) < 3:
            return False, "Username must be at least 3 characters."
        if len(password) < 6:
            return False, "Password must be at least 6 characters."

        try:
            self.database.create_user(username, hash_password_sha256(password))
            self.audit_logger.record(username, "USER_REGISTERED")
            return True, "Registration successful. You can now log in."
        except IntegrityError:
            return False, "Username already exists."
        except Exception as e:
            return False, f"Registration failed: {e}"

    def authenticate(self, username, password):
        username = username.strip()
        user = self.database.get_user(username)
        if not user:
            self.audit_logger.record(username or "unknown", "FAILED_LOGIN_UNKNOWN_USER")
            return False, "Invalid username or password."

        locked_until = user.get("locked_until")
        if locked_until:
            try:
                unlock_time = datetime.fromisoformat(locked_until)
                if datetime.now() < unlock_time:
                    remaining = int((unlock_time - datetime.now()).total_seconds())
                    self.audit_logger.record(username, "LOGIN_BLOCKED_LOCKED_ACCOUNT")
                    return False, f"Account locked. Try again in {remaining} seconds."
                self.database.reset_failed_attempts(username)
            except ValueError:
                self.database.reset_failed_attempts(username)

        if verify_password_sha256(password, user["password_hash"]):
            self.database.reset_failed_attempts(username)
            self.audit_logger.record(username, "LOGIN_SUCCESS")
            return True, "Login successful."

        attempts = self.database.increment_failed_attempts(username)
        self.audit_logger.record(username, "FAILED_LOGIN_BAD_PASSWORD")
        if attempts >= MAX_FAILED_ATTEMPTS:
            lock_until = (datetime.now() + timedelta(minutes=LOCK_MINUTES)).isoformat(timespec="seconds")
            self.database.lock_user(username, lock_until)
            self.audit_logger.record(username, "ACCOUNT_LOCKED_AFTER_FAILED_LOGINS")
            return False, f"Too many failed attempts. Account locked for {LOCK_MINUTES} minutes."
        return False, f"Invalid password. Attempts left: {MAX_FAILED_ATTEMPTS - attempts}."
