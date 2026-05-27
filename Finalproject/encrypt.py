import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from database import DatabaseManager
from hashing import sha256_file
from logs import SecurityAuditLogger
from signature import sign_file
from utils import create_backup_copy, format_bytes, now_timestamp, unique_path


MAGIC = b"SFECGCM1"
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
PBKDF2_ITERATIONS = 390_000


def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def build_package(salt, nonce, metadata, ciphertext):
    meta_bytes = json.dumps(metadata, separators=(",", ":")).encode("utf-8")
    meta_len = len(meta_bytes).to_bytes(4, byteorder="big")
    return MAGIC + salt + nonce + meta_len + meta_bytes + ciphertext


def parse_package(file_path):
    blob = open(file_path, 'rb').read()
    min_size = len(MAGIC) + SALT_SIZE + NONCE_SIZE + 4
    if len(blob) < min_size or not blob.startswith(MAGIC):
        raise ValueError("Not a valid encrypted file.")

    offset = len(MAGIC)
    salt = blob[offset : offset + SALT_SIZE]
    offset += SALT_SIZE
    nonce = blob[offset : offset + NONCE_SIZE]
    offset += NONCE_SIZE
    meta_len = int.from_bytes(blob[offset : offset + 4], byteorder="big")
    offset += 4

    meta_bytes = blob[offset : offset + meta_len]
    offset += meta_len
    if not meta_bytes or offset > len(blob):
        raise ValueError("File metadata is corrupted.")

    metadata = json.loads(meta_bytes.decode("utf-8"))
    ciphertext = blob[offset:]
    if not ciphertext:
        raise ValueError("No encrypted data in file.")

    return {
        "salt": salt,
        "nonce": nonce,
        "metadata": metadata,
        "metadata_bytes": meta_bytes,
        "ciphertext": ciphertext,
    }


def encrypt_file(file_path, password, username, database, audit_logger,
                 sign_output=False, private_key_path=None):
    src = Path(file_path)
    if not src.exists() or not src.is_file():
        raise FileNotFoundError("Selected file does not exist.")
    if not password:
        raise ValueError("Encryption password is required.")

    plaintext = src.read_bytes()
    orig_hash = sha256_file(src)
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt)

    metadata = {
        "original_name": src.name,
        "original_size": src.stat().st_size,
        "original_hash": orig_hash,
        "algorithm": "AES-256-GCM",
        "created_at": now_timestamp(),
        "owner": username,
    }
    meta_bytes = json.dumps(metadata, separators=(",", ":")).encode("utf-8")
    aad = MAGIC + meta_bytes
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    enc_blob = build_package(salt, nonce, metadata, ciphertext)

    out_path = unique_path(src.with_name(src.name + ".enc"))
    backup_path = create_backup_copy(src, username)
    with open(str(out_path), 'wb') as f:
        f.write(enc_blob)

    sig_path = ""
    if sign_output:
        if not private_key_path or not Path(private_key_path).exists():
            Path(out_path).unlink(missing_ok=True)
            raise FileNotFoundError("Private key needed to sign the file.")
        sig_path = str(sign_file(out_path, private_key_path))

    database.add_integrity_record(username, src, out_path, orig_hash, sig_path)
    audit_logger.record(username, "FILE_ENCRYPTED_AES_256_GCM", str(out_path))
    if sig_path:
        audit_logger.record(username, "DIGITAL_SIGNATURE_CREATED", sig_path)

    return {
        "encrypted_path": out_path,
        "backup_path": backup_path,
        "hash": orig_hash,
        "signature_path": sig_path,
        "size": format_bytes(len(plaintext)),
    }
