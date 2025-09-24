import os, sys, json, binascii
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

if len(sys.argv) < 3:
    print("Usage: python show_aes_key.py <meta.json path> <private.pem path>")
    sys.exit(1)

meta_file = sys.argv[1]
priv_file = sys.argv[2]

# normalize path (biar bisa relatif / absolute)
meta_file = os.path.abspath(meta_file)
priv_file = os.path.abspath(priv_file)

# cek file meta.json
if not os.path.exists(meta_file):
    print(f"Error: meta.json file not found at {meta_file}")
    sys.exit(1)

# cek private.pem
if not os.path.exists(priv_file):
    print(f"Error: private.pem not found at {priv_file}")
    sys.exit(1)

# load RSA private key
with open(priv_file, "rb") as f:
    private_key = RSA.import_key(f.read())
cipher_rsa = PKCS1_OAEP.new(private_key)

# load encrypted AES key dari meta.json
with open(meta_file, "r") as f:
    meta = json.load(f)
enc_data_key = binascii.unhexlify(meta["enc_data_key"])

# decrypt AES key
aes_key = cipher_rsa.decrypt(enc_data_key)

print("=== AES Secret Key Info ===")
print("AES Key (hex):", aes_key.hex())
print("Panjang:", len(aes_key), "bytes")
print("Meta.json path:", meta_file)
print("Private.pem path:", priv_file)
