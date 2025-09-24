import argparse
from .kms_hybrid import decrypt_file

def main():
    parser = argparse.ArgumentParser(description="Decrypt a file using AES + RSA (hybrid KMS)")
    parser.add_argument("enc_file", help="Encrypted file (.enc)")
    parser.add_argument("meta_file", help="Metadata file (.json)")
    parser.add_argument("--out", required=True, help="Output decrypted file")
    args = parser.parse_args()

    decrypt_file(args.enc_file, args.meta_file, args.out)
    print(f"[OK] File berhasil didekripsi → {args.out}")

if __name__ == "__main__":
    main()
