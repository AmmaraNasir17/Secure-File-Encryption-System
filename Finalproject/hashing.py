import hashlib
from pathlib import Path


def hash_password_sha256(password):
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def verify_password_sha256(password, expected_hash):
    return hash_password_sha256(password) == expected_hash


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(file_path, chunk_size=1024 * 1024):
    digest = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()
