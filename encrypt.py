import json
import os
from cryptography.fernet import Fernet

# 1. Baca secret key
with open("secret.key", "rb") as key_file:
    key = key_file.read()

fernet = Fernet(key)

# 2. Baca data dari JSON
with open("data.json", "r", encoding="utf-8") as f:
    data = json.load(f)

# 3. Ubah ke string JSON
data_str = json.dumps(data, ensure_ascii=False)

# 4. Encrypt
encrypted = fernet.encrypt(data_str.encode())

# 5. Cari nomor urut file .enc berikutnya
i = 1
while True:
    filename = f"data_{i}.enc"
    if not os.path.exists(filename):
        break
    i += 1

# 6. Simpan ke file baru
with open(filename, "wb") as f:
    f.write(encrypted)

print(f"✅ Data berhasil dienkripsi dan disimpan ke {filename}")
