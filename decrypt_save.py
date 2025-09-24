import json
import datetime
from cryptography.fernet import Fernet

# Baca secret key
with open("secret.key", "rb") as key_file:
    key = key_file.read()

fernet = Fernet(key)

# Baca data terenkripsi
with open("data.enc", "rb") as enc_file:
    encrypted_data = enc_file.read()

# Dekripsi
decrypted_data = fernet.decrypt(encrypted_data).decode()

# Convert string JSON ke dict biar lebih rapi
data = json.loads(decrypted_data)

# Buat nama file unik berdasarkan waktu agar tidak tertimpa
timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
output_filename = f"hasil_decrypt_{timestamp}.txt"

# Simpan hasil dekripsi ke file
with open(output_filename, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=4, ensure_ascii=False)

print(f"Hasil dekripsi berhasil disimpan ke {output_filename}")
