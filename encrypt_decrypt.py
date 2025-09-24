import json
import requests

# API endpoint
ENCRYPT_URL = "http://127.0.0.1:5000/encrypt"
DECRYPT_URL = "http://127.0.0.1:5000/decrypt"
HEADERS = {"Content-Type": "application/json"}

# 1. Baca isi data.json
with open("data.json", "r", encoding="utf-8") as f:
    original_data = json.load(f)

print("📂 Data asli dari data.json:")
print(original_data)

# 2. Encrypt ke API
payload_encrypt = {"data": json.dumps(original_data)}
resp_encrypt = requests.post(ENCRYPT_URL, headers=HEADERS, json=payload_encrypt)

if resp_encrypt.status_code == 200:
    token = resp_encrypt.json().get("token")
    print("\n🔒 Token enkripsi dibuat.")

    # Simpan token ke data.enc
    with open("data.enc", "w", encoding="utf-8") as f:
        f.write(token)
    print("📄 Token tersimpan di data.enc")
else:
    print("❌ Gagal encrypt:", resp_encrypt.text)
    exit()

# 3. Decrypt dari API
payload_decrypt = {"token": token}
resp_decrypt = requests.post(DECRYPT_URL, headers=HEADERS, json=payload_decrypt)

if resp_decrypt.status_code == 200:
    decrypted_str = resp_decrypt.json().get("data")
    decrypted_data = json.loads(decrypted_str)  # ubah balik jadi dict

    print("\n✅ Dekripsi berhasil.")
    print("📂 Data hasil dekripsi:")
    print(decrypted_data)

    # Simpan hasil dekripsi ke data_decrypted.json
    with open("data_decrypted.json", "w", encoding="utf-8") as f:
        json.dump(decrypted_data, f, indent=4, ensure_ascii=False)
    print("📄 Hasil disimpan di data_decrypted.json")

    # 4. Cek kesamaan
    if original_data == decrypted_data:
        print("\n🎉 Data dekripsi sama persis dengan data.json")
    else:
        print("\n⚠️ Data dekripsi tidak sama dengan data.json")
else:
    print("❌ Gagal decrypt:", resp_decrypt.text)
