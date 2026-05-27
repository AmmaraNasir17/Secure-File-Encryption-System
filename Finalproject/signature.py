from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from utils import KEY_DIR, safe_filename


def default_private_key_path(username):
    return KEY_DIR / f"{safe_filename(username)}_private.pem"


def default_public_key_path(username):
    return KEY_DIR / f"{safe_filename(username)}_public.pem"


def generate_rsa_key_pair(username):
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_path = default_private_key_path(username)
    public_path = default_public_key_path(username)

    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    with open(str(private_path), 'wb') as f:
        f.write(priv_bytes)
    with open(str(public_path), 'wb') as f:
        f.write(pub_bytes)
    return private_path, public_path


def sign_file(file_path, priv_key_path):
    with open(file_path, 'rb') as f:
        data = f.read()
    priv_bytes = open(str(priv_key_path), 'rb').read()
    private_key = serialization.load_pem_private_key(priv_bytes, password=None)
    sig = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    sig_path = str(file_path) + ".sig"
    with open(sig_path, 'wb') as f:
        f.write(sig)
    return sig_path


def verify_signature(file_path, sig_path, pub_key_path):
    if not Path(sig_path).exists():
        return False, "No signature file"
    if not Path(pub_key_path).exists():
        return False, "Public key missing"

    pub_bytes = open(str(pub_key_path), 'rb').read()
    public_key = serialization.load_pem_public_key(pub_bytes)
    try:
        file_data = open(file_path, 'rb').read()
        sig_data = open(sig_path, 'rb').read()
        public_key.verify(
            sig_data,
            file_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True, "Signature is valid"
    except InvalidSignature:
        return False, "Bad signature - file may be modified"
    except Exception as e:
        return False, f"Error checking signature: {e}"
