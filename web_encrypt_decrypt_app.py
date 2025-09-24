import os
import time
import json
import sqlite3
import uuid
from datetime import datetime
from flask import Flask, request, render_template_string, send_file, jsonify
from werkzeug.utils import secure_filename
from kms_hybrid_addon import encrypt_file, decrypt_file
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import NoEncryption

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
KEYS_FOLDER = "keys"
DB_PATH = "file_records.db"
ALLOWED_EXTENSIONS = {"json", "csv", "txt", "png", "jpg", "jpeg", "gif", "pdf", "xls", "xlsx", "doc", "docx"}
TEXT_EXTENSIONS = {"json", "csv", "txt"}
IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(KEYS_FOLDER, exist_ok=True)

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id TEXT PRIMARY KEY,
            filename TEXT,
            enc_path TEXT,
            internal_meta_path TEXT,
            public_meta_path TEXT,
            sig_path TEXT,
            uploaded_at TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

PRIVATE_KEY_PATH = os.path.join(KEYS_FOLDER, "private_key.pem")
PUBLIC_KEY_PATH = os.path.join(KEYS_FOLDER, "public_key.pem")

def generate_and_save_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    with open(PRIVATE_KEY_PATH, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption()
        ))

    with open(PUBLIC_KEY_PATH, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    return private_key, public_key

def load_keys():
    if os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(PUBLIC_KEY_PATH):
        with open(PRIVATE_KEY_PATH, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(PUBLIC_KEY_PATH, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
        return private_key, public_key
    else:
        return generate_and_save_keys()

PRIVATE_KEY, PUBLIC_KEY = load_keys()

def sign_file(path):
    with open(path, "rb") as f:
        data = f.read()
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    file_hash = digest.finalize()
    signature = PRIVATE_KEY.sign(
        file_hash,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return signature

def verify_file(path, signature):
    with open(path, "rb") as f:
        data = f.read()
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    file_hash = digest.finalize()
    try:
        PUBLIC_KEY.verify(
            signature,
            file_hash,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def file_size(path):
    try:
        return round(os.path.getsize(path) / 1024, 2)
    except Exception:
        return 0

def calculate_speed(input_size_kb, duration):
    if duration == 0:
        return 0
    return round((input_size_kb / 1024) / duration, 2)  # MBps

@app.route('/')
def index():
    return render_template_string(HTML)

@app.route('/encrypt', methods=['POST'])
def encrypt_route():
    try:
        if "file" not in request.files:
            return jsonify({"error": "No file uploaded"}), 400
        file = request.files["file"]
        if file.filename == '':
            return jsonify({"error": "No selected file"}), 400
        if not allowed_file(file.filename):
            return jsonify({"error": "File type not allowed"}), 400

        file.seek(0, os.SEEK_END)
        size = file.tell()
        file.seek(0)
        if size > MAX_FILE_SIZE:
            return jsonify({"error": f"File too large. Max size is {MAX_FILE_SIZE / (1024 * 1024)} MB"}), 400

        filename = secure_filename(file.filename)
        input_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(input_path)

        output_enc = input_path + ".enc"
        output_internal_meta = input_path + ".meta.internal.json"
        output_public_meta = input_path + ".meta.json"

        start_time = time.time()
        encrypt_file(input_path, output_enc, output_internal_meta)
        duration = time.time() - start_time

        sig = sign_file(output_enc)
        sig_path = output_enc + ".sig"
        with open(sig_path, "wb") as f:
            f.write(sig)

        token_id = str(uuid.uuid4())
        with open(output_public_meta, "w") as f:
            json.dump({"token_id": token_id}, f)

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("INSERT INTO files (id, filename, enc_path, internal_meta_path, public_meta_path, sig_path, uploaded_at) VALUES (?,?,?,?,?,?,?)",
                  (token_id, filename, output_enc, output_internal_meta, output_public_meta, sig_path, datetime.utcnow().isoformat()))
        conn.commit()
        conn.close()

        return jsonify({
            "encrypted_file": os.path.basename(output_enc),
            "metadata_file": os.path.basename(output_public_meta),
            "signature_file": os.path.basename(sig_path),
            "duration": round(duration,3),
            "speed_MBps": calculate_speed(file_size(input_path), duration),
            "input_size": file_size(input_path),
            "output_size": file_size(output_enc)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/decrypt', methods=['POST'])
def decrypt_route():
    try:
        if "file_meta" not in request.files:
            return jsonify({"error": "Upload meta.json"}), 400
        file_meta = request.files["file_meta"]
        if file_meta.filename == '':
            return jsonify({"error": "No selected meta.json file"}), 400
        if not allowed_file(file_meta.filename) or not file_meta.filename.endswith(".json"):
            return jsonify({"error": "Invalid metadata file type. Must be .json"}), 400

        meta_path = os.path.join(app.config["UPLOAD_FOLDER"], secure_filename(file_meta.filename))
        file_meta.save(meta_path)

        with open(meta_path,"r") as f:
            meta = json.load(f)
        token_id = meta.get("token_id")
        if not token_id:
            return jsonify({"error":"No token_id in metadata"}),400

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT enc_path, internal_meta_path, sig_path, filename FROM files WHERE id=?", (token_id,))
        row = c.fetchone()
        conn.close()
        if not row:
            return jsonify({"error":"Token not found"}),404

        enc_path, internal_meta, sig_path, original_filename = row
        with open(sig_path,"rb") as f:
            sig = f.read()
        
        if not verify_file(enc_path, sig):
            return jsonify({"error": "Signature verification failed. File might be tampered with."}), 403

        output_format = request.form.get("output_format","txt")
        original_name_base = os.path.splitext(original_filename)[0]
        output_path = os.path.join(app.config["UPLOAD_FOLDER"], f"decrypted_{original_name_base}_{uuid.uuid4().hex}.{output_format}")

        start_time = time.time()
        decrypt_file(enc_path, internal_meta, output_path)
        duration = time.time() - start_time

        return jsonify({
            "decrypted_file": os.path.basename(output_path),
            "duration": round(duration, 3),
            "speed_MBps": calculate_speed(file_size(enc_path), duration),
            "input_size": file_size(enc_path),
            "output_size": file_size(output_path)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/verify', methods=['POST'])
def verify_route():
    try:
        if "meta_file" not in request.files:
            return jsonify({"error": "No meta.json uploaded"}), 400
        meta_file = request.files["meta_file"]
        if meta_file.filename == '':
            return jsonify({"error": "No selected meta.json file"}), 400
        if not allowed_file(meta_file.filename) or not meta_file.filename.endswith(".json"):
            return jsonify({"error": "Invalid metadata file type. Must be .json"}), 400

        meta_path = os.path.join(app.config["UPLOAD_FOLDER"], secure_filename(meta_file.filename))
        meta_file.save(meta_path)

        with open(meta_path,"r") as f:
            meta = json.load(f)
        token_id = meta.get("token_id")
        if not token_id:
            return jsonify({"error":"No token_id in metadata"}),400

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT enc_path, sig_path FROM files WHERE id=?", (token_id,))
        row = c.fetchone()
        conn.close()
        if not row:
            return jsonify({"error":"Token not found in DB"}),404

        enc_path, sig_path = row
        with open(sig_path,"rb") as f:
            sig = f.read()

        if verify_file(enc_path, sig):
            return jsonify({"status":"VALID"})
        else:
            return jsonify({"status":"TIDAK VALID"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/download/<path:filename>")
def download_file(filename):
    file_full_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    if os.path.exists(file_full_path):
        return send_file(file_full_path, as_attachment=True)
    return jsonify({"error": "File not found"}), 404

HTML = """
<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <title>Encrypt / Decrypt</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css">
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
  <style>
    .preview-image {
      max-width: 100%;
      height: auto;
    }
    .preview-text {
      white-space: pre-wrap;
      word-wrap: break-word;
      max-height: 300px;
      overflow-y: auto;
      border: 1px solid #dee2e6;
      padding: 10px;
      background-color: #f8f9fa;
    }
  </style>
</head>
<body class="p-4">
  <div class="container">
    <h2 class="mb-4">🔐 Enkripsi / Dekripsi File + RSA Signature</h2>

    <!-- Enkripsi -->
    <div class="card mb-4">
      <div class="card-body">
        <h4>Enkripsi File</h4>
        <small class="text-muted">Bisa upload file: JSON, CSV, TXT, PNG, JPG, JPEG, GIF, PDF, XLS, XLSX, DOC, DOCX (Max 5 MB)</small>
        <form id="encryptForm">
          <input type="file" name="file" class="form-control mb-2" id="encryptFileInput">
          <button type="submit" class="btn btn-primary">Encrypt</button>
        </form>
        <div id="encryptResult" class="mt-3"></div>

        <!-- Tabs untuk Enkripsi -->
        <ul class="nav nav-tabs mt-3" id="encryptTabs" role="tablist">
          <li class="nav-item" role="presentation">
            <button class="nav-link active" id="encrypt-info-tab" data-bs-toggle="tab" data-bs-target="#encrypt-info" type="button" role="tab" aria-controls="encrypt-info" aria-selected="true">Info</button>
          </li>
          <li class="nav-item" role="presentation">
            <button class="nav-link" id="encrypt-preview-tab" data-bs-toggle="tab" data-bs-target="#encrypt-preview" type="button" role="tab" aria-controls="encrypt-preview" aria-selected="false">Preview</button>
          </li>
        </ul>
        <div class="tab-content" id="encryptTabContent">
          <div class="tab-pane fade show active" id="encrypt-info" role="tabpanel" aria-labelledby="encrypt-info-tab">
            <div class="card card-body mt-2">
              <h5>Informasi Enkripsi</h5>
              <p><strong>Durasi Proses:</strong> <span id="encryptDuration">N/A</span> detik</p>
              <p><strong>Kecepatan:</strong> <span id="encryptSpeed">N/A</span> MBps</p>
              <p><strong>Ukuran Input:</strong> <span id="encryptInputSize">N/A</span> KB</p>
              <p><strong>Ukuran Output:</strong> <span id="encryptOutputSize">N/A</span> KB</p>
            </div>
          </div>
          <div class="tab-pane fade" id="encrypt-preview" role="tabpanel" aria-labelledby="encrypt-preview-tab">
            <div class="card card-body mt-2">
              <h5>Preview</h5>
              <div id="encryptPreviewContent" class="preview-text">Pilih file untuk melihat preview.</div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Dekripsi -->
    <div class="card mb-4">
      <div class="card-body">
        <h4>Dekripsi File</h4>
        <form id="decryptForm">
          <label class="form-label">Upload public meta.json</label>
          <input type="file" name="file_meta" class="form-control mb-2">
          <div class="mt-2">
            <label class="form-label">Format output:</label>
            <select id="outputFormat" class="form-select w-auto">
              <option value="csv">CSV</option>
              <option value="json">JSON</option>
              <option value="txt">TXT</option>
              <option value="docx">Word (DOCX)</option>
              <option value="xlsx">Excel (XLSX)</option>
              <option value="pdf">PDF</option>
              <option value="png">PNG</option>
              <option value="jpg">JPG</option>
            </select>
          </div>
          <button type="submit" class="btn btn-success mt-2">Decrypt</button>
        </form>
        <div id="decryptResult" class="mt-3"></div>

        <!-- Tabs untuk Dekripsi -->
        <ul class="nav nav-tabs mt-3" id="decryptTabs" role="tablist">
          <li class="nav-item" role="presentation">
            <button class="nav-link active" id="decrypt-info-tab" data-bs-toggle="tab" data-bs-target="#decrypt-info" type="button" role="tab" aria-controls="decrypt-info" aria-selected="true">Info</button>
          </li>
          <li class="nav-item" role="presentation">
            <button class="nav-link" id="decrypt-preview-tab" data-bs-toggle="tab" data-bs-target="#decrypt-preview" type="button" role="tab" aria-controls="decrypt-preview" aria-selected="false">Preview</button>
          </li>
        </ul>
        <div class="tab-content" id="decryptTabContent">
          <div class="tab-pane fade show active" id="decrypt-info" role="tabpanel" aria-labelledby="decrypt-info-tab">
            <div class="card card-body mt-2">
              <h5>Informasi Dekripsi</h5>
              <p><strong>Durasi Proses:</strong> <span id="decryptDuration">N/A</span> detik</p>
              <p><strong>Kecepatan:</strong> <span id="decryptSpeed">N/A</span> MBps</p>
              <p><strong>Ukuran Input:</strong> <span id="decryptInputSize">N/A</span> KB</p>
              <p><strong>Ukuran Output:</strong> <span id="decryptOutputSize">N/A</span> KB</p>
            </div>
          </div>
          <div class="tab-pane fade" id="decrypt-preview" role="tabpanel" aria-labelledby="decrypt-preview-tab">
            <div class="card card-body mt-2">
              <h5>Preview</h5>
              <div id="decryptPreviewContent">Pilih file untuk melihat preview.</div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Verifikasi -->
    <div class="card mb-4">
      <div class="card-body">
        <h4>Verifikasi Signature</h4>
        <form id="verifyForm">
          <label class="form-label">Upload public meta.json</label>
          <input type="file" name="meta_file" class="form-control mb-2">
          <button type="submit" class="btn btn-warning">Verify</button>
        </form>
        <div id="verifyResult" class="mt-3"></div>
      </div>
    </div>
  </div>

  <script>
    function makeDownloadLink(filename, text) {
      return `<a href="/download/${encodeURIComponent(filename)}" class="btn btn-sm btn-outline-dark me-2" target="_blank">${text}</a>`;
    }

    function getFileExtension(filename) {
      return filename.split('.').pop().toLowerCase();
    }

    // Preview saat pilih file untuk encrypt
    document.getElementById('encryptFileInput').addEventListener('change', function(event) {
      const file = event.target.files[0];
      const previewContent = document.getElementById('encryptPreviewContent');
      if (file) {
        const reader = new FileReader();
        reader.onload = function(e) {
          const bytes = new Uint8Array(e.target.result);
          let binary = '';
          for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
          }
          const base64String = btoa(binary);
          previewContent.textContent = base64String;
        };
        reader.readAsArrayBuffer(file);
      } else {
        previewContent.innerHTML = `Pilih file untuk melihat preview.`;
      }
    });

    async function handleForm(formId, url, resultId, isDecrypt=false) {
      const form = document.getElementById(formId);
      form.addEventListener("submit", async (e) => {
        e.preventDefault();
        const formData = new FormData(form);
        if (isDecrypt) {
          const format = document.getElementById("outputFormat").value;
          formData.append("output_format", format);
        }
        try {
          const res = await fetch(url, { method: "POST", body: formData });
          const data = await res.json();
          const resultBox = document.getElementById(resultId);

          if (data.error) {
            resultBox.innerHTML = `<div class="alert alert-danger">${data.error}</div>`;
          } else if (data.status) {
            const color = data.status === "VALID" ? "success" : "danger";
            resultBox.innerHTML = `<div class="alert alert-${color}">Signature: ${data.status}</div>`;
          } else {
            let links = "";
            if (data.encrypted_file) links += makeDownloadLink(data.encrypted_file, "Encrypted File");
            if (data.metadata_file) links += makeDownloadLink(data.metadata_file, "Public Metadata");
            if (data.signature_file) links += makeDownloadLink(data.signature_file, "Signature File");
            if (data.decrypted_file) links += makeDownloadLink(data.decrypted_file, "Decrypted File");

            resultBox.innerHTML = `<div class="alert alert-success">Proses berhasil!</div>` + links;

            if (formId === "encryptForm") {
              document.getElementById('encryptDuration').textContent = data.duration;
              document.getElementById('encryptSpeed').textContent = data.speed_MBps;
              document.getElementById('encryptInputSize').textContent = data.input_size;
              document.getElementById('encryptOutputSize').textContent = data.output_size;
            } else if (formId === "decryptForm") {
              document.getElementById('decryptDuration').textContent = data.duration;
              document.getElementById('decryptSpeed').textContent = data.speed_MBps;
              document.getElementById('decryptInputSize').textContent = data.input_size;
              document.getElementById('decryptOutputSize').textContent = data.output_size;

              if (data.decrypted_file) {
                const decryptedFilenameOnly = data.decrypted_file;
                const ext = getFileExtension(decryptedFilenameOnly);
                const preview = document.getElementById('decryptPreviewContent');
                new bootstrap.Tab(document.getElementById('decrypt-preview-tab')).show();

                if (['json','csv','txt'].includes(ext)) {
                  const textRes = await fetch(`/download/${encodeURIComponent(decryptedFilenameOnly)}`);
                  const textData = await textRes.text();
                  preview.textContent = textData;
                } else if (['png','jpg','jpeg','gif'].includes(ext)) {
                  preview.innerHTML = `<img src="/download/${encodeURIComponent(decryptedFilenameOnly)}" class="preview-image">`;
                } else {
                  preview.innerHTML = `<div class="alert alert-info">Preview tidak tersedia untuk tipe file ini.</div>`;
                }
              }
            }
          }
        } catch (err) {
          document.getElementById(resultId).innerHTML = `<div class="alert alert-danger">Server error: ${err.message}</div>`;
        }
      });
    }

    handleForm("encryptForm", "/encrypt", "encryptResult");
    handleForm("decryptForm", "/decrypt", "decryptResult", true);
    handleForm("verifyForm", "/verify", "verifyResult");
  </script>
</body>
</html>
"""

if __name__ == "__main__":
    app.run(debug=True)
