import argparse
from .kms_hybrid import encrypt_file

def main():
    parser = argparse.ArgumentParser(description="Encrypt a file using AES + RSA (hybrid KMS)")
    parser.add_argument("input", help="Input file to encrypt")
    parser.add_argument("--out-enc", required=True, help="Output encrypted file")
    parser.add_argument("--out-meta", required=True, help="Output metadata file (JSON)")
    args = parser.parse_args()

    encrypt_file(args.input, args.out_enc, args.out_meta)
    print(f"[OK] File dienkripsi → {args.out_enc}")
    print(f"[OK] Metadata disimpan → {args.out_meta}")

if __name__ == "__main__":
    main()
