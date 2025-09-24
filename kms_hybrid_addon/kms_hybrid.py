import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import json

PRIVATE_KEY_FILE = "kms_hybrid_addon/private.pem"
PUBLIC_KEY_FILE = "kms_hybrid_addon/public.pem"

# ======================
# RSA Key Management
# ======================
def ensure_rsa_keys():
    """Generate RSA keys once if not exist."""
    if not os.path.exists(PRIVATE_KEY_FILE) or not os.path.exists(PUBLIC_KEY_FILE):
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()

        os.makedirs("kms_hybrid_addon", exist_ok=True)
        with open(PRIVATE_KEY_FILE, "wb") as f:
            f.write(private_key)
        with open(PUBLIC_KEY_FILE, "wb") as f:
            f.write(public_key)


def load_private_key():
    ensure_rsa_keys()
    with open(PRIVATE_KEY_FILE, "rb") as f:
        return RSA.import_key(f.read())


def load_public_key():
    ensure_rsa_keys()
    with open(PUBLIC_KEY_FILE, "rb") as f:
        return RSA.import_key(f.read())


# ======================
# Hybrid AES + RSA
# ======================
def encrypt_file(input_file, output_enc_file, output_meta_file):
    # Generate AES data key
    data_key = get_random_bytes(32)  # AES-256

    # Encrypt file content with AES
    cipher_aes = AES.new(data_key, AES.MODE_GCM)
    with open(input_file, "rb") as f:
        plaintext = f.read()
    ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext)

    # Encrypt data_key with RSA public key
    recipient_key = load_public_key()
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_data_key = cipher_rsa.encrypt(data_key)

    # Save encrypted file
    with open(output_enc_file, "wb") as f:
        for x in (cipher_aes.nonce, tag, ciphertext):
            f.write(x)

    # Save metadata
    metadata = {
        "enc_data_key": enc_data_key.hex(),
        "aes_mode": "GCM",
        "key_size": 256,
    }
    with open(output_meta_file, "w") as f:
        json.dump(metadata, f, indent=2)


def decrypt_file(enc_file, meta_file, output_file):
    with open(enc_file, "rb") as f:
        nonce, tag, ciphertext = f.read(16), f.read(16), f.read()

    with open(meta_file, "r") as f:
        metadata = json.load(f)

    enc_data_key = bytes.fromhex(metadata["enc_data_key"])

    # Decrypt AES data key
    private_key = load_private_key()
    cipher_rsa = PKCS1_OAEP.new(private_key)
    data_key = cipher_rsa.decrypt(enc_data_key)

    # Decrypt file content
    cipher_aes = AES.new(data_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)

    with open(output_file, "wb") as f:
        f.write(plaintext)
