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

SECRET_KEY = load_or_create_key()
fernet = Fernet(SECRET_KEY)

# ---------------- API ROUTES ----------------

@app.route("/")
def home():
    return "API Enkripsi & Dekripsi aktif ✅"

@app.route("/encrypt", methods=["POST"])
def encrypt_data():
    data = request.get_json()
    if not data or "data" not in data:
        return jsonify({"error": "Harap kirim field 'data' di JSON"}), 400
    try:
        token = fernet.encrypt(data["data"].encode()).decode()
        return jsonify({"token": token})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/decrypt", methods=["POST"])
def decrypt_data():
    data = request.get_json()
    if not data or "token" not in data:
        return jsonify({"error": "Harap kirim field 'token' di JSON"}), 400
    try:
        text = fernet.decrypt(data["token"].encode()).decode()
        return jsonify({"data": text})
    except Exception:
        return jsonify({"error": "Token tidak valid"}), 400

if __name__ == "__main__":
    app.run(debug=True)
