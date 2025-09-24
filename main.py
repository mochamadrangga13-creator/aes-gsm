from fastapi import FastAPI, UploadFile, File
from fastapi.responses import FileResponse, JSONResponse
import encrypt
import os

app = FastAPI()

# Endpoint untuk enkripsi file JSON
@app.post("/encrypt")
async def encrypt_file(file: UploadFile = File(...)):
    input_path = f"temp_{file.filename}"
    output_path = "encrypted.enc"

    # simpan file sementara
    with open(input_path, "wb") as f:
        f.write(await file.read())

    # jalankan fungsi enkripsi
    encrypt.encrypt_json(input_path, output_path)

    # hapus file input sementara
    os.remove(input_path)

    return FileResponse(output_path, filename=output_path)


# Endpoint untuk dekripsi file
@app.post("/decrypt")
async def decrypt_file(file: UploadFile = File(...)):
    input_path = f"temp_{file.filename}"
    output_path = "decrypted.json"

    # simpan file sementara
    with open(input_path, "wb") as f:
        f.write(await file.read())

    # jalankan fungsi dekripsi
    encrypt.decrypt_json(input_path, output_path)

    # hapus file input sementara
    os.remove(input_path)

    return FileResponse(output_path, filename=output_path)


@app.get("/")
def root():
    return JSONResponse({"message": "API Enkripsi JSON dengan AES siap 🚀"})
