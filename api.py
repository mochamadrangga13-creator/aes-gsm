from flask import Flask, request, jsonify
from cryptography.fernet import Fernet
import os

app = Flask(__name__)

KEY_FILE = "secret.key"

# 🔑 Load atau buat secret key sekali
def load_or_create_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            key = f.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    return key

key = load_or_create_key()
fernet = Fernet(key)

# ==== Endpoint Root ====
@app.route("/")
def home():
    return "API Python untuk Enkripsi & Dekripsi sudah jalan ✅"

# ==== Endpoint Enkripsi ====
@app.route("/encrypt", methods=["POST"])
def encrypt_data():
    try:
        data = request.json.get("data")
        if not data:
            return jsonify({"error": "Field 'data' wajib ada"}), 400
        encrypted = fernet.encrypt(data.encode())
        return jsonify({"encrypted": encrypted.decode()})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# ==== Endpoint Dekripsi ====
@app.route("/decrypt", methods=["POST"])
def decrypt_data():
    try:
        token = request.json.get("data")
        if not token:
            return jsonify({"error": "Field 'data' wajib ada"}), 400
        decrypted = fernet.decrypt(token.encode())
        return jsonify({"decrypted": decrypted.decode()})
    except Exception:
        return jsonify({"error": "Token tidak valid"}), 400

if __name__ == "__main__":
    app.run(debug=True)
