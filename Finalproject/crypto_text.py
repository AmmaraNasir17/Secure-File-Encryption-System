import base64
import json
import os

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

try:
    from cryptography.hazmat.decrepit.ciphers import algorithms as old_algorithms
except:
    from cryptography.hazmat.primitives.ciphers import algorithms as old_algorithms


TEXT_CRYPTO_METHODS = (
    "Caesar",
    "Vigenere",
    "AES",
    "DES",
    "Rail Fence",
)


def encrypt_text(method, text, key):
    m = method.strip().lower()
    if m == "caesar":
        return caesar(text, get_number(key, 3))
    if m == "vigenere":
        return vigenere(text, key, True)
    if m == "aes":
        return aes_work(text, key, True)
    if m == "des":
        return des_work(text, key, True)
    if m == "rail fence":
        return rail_encrypt(text, get_number(key, 3))
    raise ValueError("Choose a valid method.")


def decrypt_text(method, text, key):
    m = method.strip().lower()
    if m == "caesar":
        return caesar(text, -get_number(key, 3))
    if m == "vigenere":
        return vigenere(text, key, False)
    if m == "aes":
        return aes_work(text, key, False)
    if m == "des":
        return des_work(text, key, False)
    if m == "rail fence":
        return rail_decrypt(text, get_number(key, 3))
    raise ValueError("Choose a valid method.")


def get_number(val, default):
    val = val.strip()
    if not val:
        return default
    return int(val)


def caesar(text, shift):
    shift %= 26
    result = []
    for char in text:
        if char.isalpha():
            base = ord("A") if char.isupper() else ord("a")
            result.append(chr((ord(char) - base + shift) % 26 + base))
        else:
            result.append(char)
    return "".join(result)


def clean_vigenere_key(key):
    letters = [ord(char.lower()) - ord("a") for char in key if char.isalpha()]
    if not letters:
        raise ValueError("Vigenere needs letters in the key.")
    return letters


def vigenere(text, key, enc):
    shifts = clean_vigenere_key(key)
    result = []
    pos = 0
    for char in text:
        if char.isalpha():
            shift = shifts[pos % len(shifts)]
            if not enc:
                shift = -shift
            base = ord("A") if char.isupper() else ord("a")
            result.append(chr((ord(char) - base + shift) % 26 + base))
            pos += 1
        else:
            result.append(char)
    return "".join(result)


def pack(d):
    return json.dumps(d, separators=(",", ":"))


def unpack(txt, alg):
    try:
        d = json.loads(txt)
    except json.JSONDecodeError as e:
        raise ValueError("Bad cipher text format") from e
    if d.get("alg") != alg:
        raise ValueError(f"Wrong algorithm: {alg}")
    return d


def b64(data):
    return base64.urlsafe_b64encode(data).decode("ascii")


def unb64(txt):
    return base64.urlsafe_b64decode(txt.encode("ascii"))


def need_key(key, method):
    k = key.strip()
    if not k:
        raise ValueError(f"{method} needs a key.")
    return k


def make_key(password, salt, length):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=200_000,
    )
    return kdf.derive(password.encode("utf-8"))


def aes_work(text, key, enc):
    pwd = need_key(key, "AES")
    if enc:
        salt = os.urandom(16)
        nonce = os.urandom(12)
        cipher_key = make_key(pwd, salt, 32)
        ciphertext = AESGCM(cipher_key).encrypt(nonce, text.encode("utf-8"), None)
        return pack({"alg": "AES", "salt": b64(salt), "nonce": b64(nonce), "text": b64(ciphertext)})
    d = unpack(text, "AES")
    cipher_key = make_key(pwd, unb64(d["salt"]), 32)
    plain = AESGCM(cipher_key).decrypt(unb64(d["nonce"]), unb64(d["text"]), None)
    return plain.decode("utf-8")


def des_work(text, key, enc):
    pwd = need_key(key, "DES")
    if enc:
        salt = os.urandom(8)
        iv = os.urandom(8)
        cipher_key = make_key(pwd, salt, 24)
        padder = padding.PKCS7(64).padder()
        padded = padder.update(text.encode("utf-8")) + padder.finalize()
        encryptor = Cipher(old_algorithms.TripleDES(cipher_key), modes.CBC(iv)).encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()
        return pack({"alg": "DES", "salt": b64(salt), "iv": b64(iv), "text": b64(ciphertext)})
    d = unpack(text, "DES")
    cipher_key = make_key(pwd, unb64(d["salt"]), 24)
    decryptor = Cipher(old_algorithms.TripleDES(cipher_key), modes.CBC(unb64(d["iv"]))).decryptor()
    padded = decryptor.update(unb64(d["text"])) + decryptor.finalize()
    unpadder = padding.PKCS7(64).unpadder()
    plain = unpadder.update(padded) + unpadder.finalize()
    return plain.decode("utf-8")


def rail_encrypt(text, num_rails):
    if num_rails < 2:
        raise ValueError("Need at least 2 rails.")
    if len(text) <= 1:
        return text
    num_rails = min(num_rails, len(text))
    rows = [""] * num_rails
    row = 0
    direction = 1
    for char in text:
        rows[row] += char
        if row == 0:
            direction = 1
        elif row == num_rails - 1:
            direction = -1
        row += direction
    return "".join(rows)


def rail_decrypt(text, num_rails):
    if num_rails < 2:
        raise ValueError("Need at least 2 rails.")
    if len(text) <= 1:
        return text
    num_rails = min(num_rails, len(text))
    order = []
    row = 0
    direction = 1
    for _ in text:
        order.append(row)
        if row == 0:
            direction = 1
        elif row == num_rails - 1:
            direction = -1
        row += direction
    counts = [order.count(n) for n in range(num_rails)]
    rows = []
    idx = 0
    for count in counts:
        rows.append(list(text[idx : idx + count]))
        idx += count
    result = []
    for n in order:
        result.append(rows[n].pop(0))
    return "".join(result)


