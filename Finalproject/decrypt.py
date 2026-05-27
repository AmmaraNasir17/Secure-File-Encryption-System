from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from database import DatabaseManager
from encrypt import MAGIC, derive_key, parse_package
from hashing import sha256_bytes
from logs import SecurityAuditLogger
from signature import verify_signature
from utils import unique_path


def decrypt_file(enc_file, password, username, database, audit_logger, 
                 output_folder=None, verify_sig=False, pub_key_path=None, 
                 sig_path=None):
    enc_path = Path(enc_file)
    if not enc_path.exists() or not enc_path.is_file():
        raise FileNotFoundError("Encrypted file does not exist.")
    if not password:
        raise ValueError("Decryption password is required.")

    sig_ok = None
    sig_msg = "Signature verification was not requested."
    integ_record = database.get_integrity_by_encrypted_file(enc_path)

    if verify_sig:
        chosen_sig = sig_path or (integ_record or {}).get("signature_path") or str(enc_path) + ".sig"
        if not pub_key_path:
            sig_ok = False
            sig_msg = "Public key is required for signature verification."
        else:
            sig_ok, sig_msg = verify_signature(enc_path, chosen_sig, pub_key_path)
        audit_logger.record(username, "DIGITAL_SIGNATURE_VERIFICATION", str(enc_path))

    try:
        package = parse_package(enc_path)
        key = derive_key(password, package["salt"])
        aad = MAGIC + package["metadata_bytes"]
        plaintext = AESGCM(key).decrypt(package["nonce"], package["ciphertext"], aad)
    except InvalidTag as e:
        audit_logger.record(username, "DECRYPTION_FAILED_AUTH_OR_TAMPERED", str(enc_path))
        raise ValueError("Wrong password or file was modified/corrupted.") from e

    metadata = package["metadata"]
    output_name = f"decrypted_{metadata.get('original_name', enc_path.stem)}"
    dest_folder = Path(output_folder) if output_folder else enc_path.parent
    dest_folder.mkdir(parents=True, exist_ok=True)
    out_path = unique_path(dest_folder / output_name)
    with open(str(out_path), 'wb') as f:
        f.write(plaintext)

    dec_hash = sha256_bytes(plaintext)
    expected_hash = (integ_record or {}).get("hash_value") or metadata.get("original_hash", "")
    integ_ok = bool(expected_hash) and dec_hash == expected_hash

    if integ_ok:
        audit_logger.record(username, "FILE_DECRYPTED_INTEGRITY_OK", str(out_path))
        integ_msg = "File integrity verified successfully."
    else:
        audit_logger.record(username, "INTEGRITY_FAILURE_FILE_HASH_MISMATCH", str(enc_path))
        integ_msg = "File integrity compromised."

    return {
        "output_path": out_path,
        "integrity_ok": integ_ok,
        "integrity_message": integ_msg,
        "expected_hash": expected_hash,
        "actual_hash": dec_hash,
        "signature_ok": sig_ok,
        "signature_message": sig_msg,
    }
