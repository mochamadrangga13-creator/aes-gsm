import json
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from getpass import getpass

# Fungsi untuk buat key dari password
def get_key_from_password(password):
    # hash password jadi 32 byte (AES-256)
    return hashlib.sha256(password.encode()).digest()

def encrypt_json(input_file, output_file, password):
    key = get_key_from_password(password)

    with open(input_file, "r") as f:
        data = f.read().encode()

    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data)

    # Simpan: nonce + tag + ciphertext
    file_out = base64.b64encode(nonce + tag + ciphertext)

    with open(output_file, "wb") as f:
        f.write(file_out)

    print(f"✅ File {input_file} berhasil dienkripsi ke {output_file}")

def decrypt_json(input_file, output_file, password):
    key = get_key_from_password(password)

    with open(input_file, "rb") as f:
        enc_data = base64.b64decode(f.read())

    nonce = enc_data[:16]
    tag = enc_data[16:32]
    ciphertext = enc_data[32:]

    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)

    with open(output_file, "w") as f:
        f.write(data.decode())

    print(f"✅ File {input_file} berhasil didekripsi ke {output_file}")

if __name__ == "__main__":
    password = getpass("🔑 1303041334: ")

    encrypt_json("data.json", "data.enc", password)
    decrypt_json("data.enc", "data_decrypted.json", password)
