import os
import re
import shutil
from datetime import datetime
from pathlib import Path


APP_TITLE = "Secure File Encryption & Cryptography System"
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "security_system.db"
BACKUP_DIR = BASE_DIR / "secure_backups"
KEY_DIR = BASE_DIR / "keys"
LOG_DIR = BASE_DIR / "logs"

COLORS = {
    "bg": "#f4f7fb",
    "panel": "#ffffff",
    "sidebar": "#101828",
    "sidebar_hover": "#1d2939",
    "primary": "#1d4ed8",
    "primary_dark": "#1e40af",
    "success": "#047857",
    "warning": "#b45309",
    "danger": "#b42318",
    "text": "#101828",
    "muted": "#667085",
    "border": "#d0d5dd",
    "soft": "#eef4ff",
}


def ensure_app_folders():
    for folder in (BACKUP_DIR, KEY_DIR, LOG_DIR):
        folder.mkdir(parents=True, exist_ok=True)


def now_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def iso_timestamp():
    return datetime.now().isoformat(timespec="seconds")


def safe_filename(name):
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", name.strip())
    return cleaned or "file"


def unique_path(p):
    if not p.exists():
        return p

    stem = p.stem
    suffix = p.suffix
    parent = p.parent
    counter = 1
    while True:
        candidate = parent / f"{stem}_{counter}{suffix}"
        if not candidate.exists():
            return candidate
        counter += 1


def create_backup_copy(src_path, username="system"):
    ensure_app_folders()
    source = Path(src_path)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_name = f"{safe_filename(username)}_{ts}_{safe_filename(source.name)}"
    backup_path = unique_path(BACKUP_DIR / backup_name)
    shutil.copy2(source, backup_path)
    return backup_path


def format_bytes(size):
    units = ("B", "KB", "MB", "GB")
    amount = float(size)
    for unit in units:
        if amount < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(amount)} {unit}"
            return f"{amount:.1f} {unit}"
        amount /= 1024


def password_strength(pwd):
    score = 0
    checks = [
        len(pwd) >= 8,
        bool(re.search(r"[A-Z]", pwd)),
        bool(re.search(r"[a-z]", pwd)),
        bool(re.search(r"\d", pwd)),
        bool(re.search(r"[^A-Za-z0-9]", pwd)),
    ]
    score = sum(1 for c in checks if c)
    if not pwd:
        return 0, "Enter a password"
    if score <= 2:
        return score, "Weak: use 8+ chars, numbers, symbols, upper/lowercase"
    if score <= 4:
        return score, "Medium: add another character type"
    return score, "Strong password"


def center_window(window, w, h):
    sw = window.winfo_screenwidth()
    sh = window.winfo_screenheight()
    x = int((sw - w) / 2)
    y = int((sh - h) / 2)
    window.geometry(f"{w}x{h}+{x}+{y}")


def open_folder(path):
    os.startfile(Path(path).resolve())


ensure_app_folders()
