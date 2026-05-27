import logging
from pathlib import Path

from database import DatabaseManager
from utils import LOG_DIR


class SecurityAuditLogger:
    def __init__(self, database):
        self.database = database
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        self.log_file = LOG_DIR / "security_audit.log"
        logging.basicConfig(
            filename=str(self.log_file),
            level=logging.INFO,
            format="%(asctime)s | %(levelname)s | %(message)s",
        )

    def record(self, username, action, filename=""):
        user = username or "anonymous"
        fname = filename or ""
        self.database.add_log(user, action, fname)
        logging.info("user=%s action=%s file=%s", user, action, fname)
