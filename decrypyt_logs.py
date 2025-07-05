from cryptography.fernet import Fernet
import os

KEY_FILE = "fernet.key"
ENC_FILE = "datasets/cicids_logs_encrypted.jsonl"
OUT_FILE = "datasets/cicids_logs.jsonl"

# Load key
if not os.path.exists(KEY_FILE):
    print(f"[ERROR] Missing key file: {KEY_FILE}")
    exit(1)

with open(KEY_FILE, 'rb') as f:
    key = f.read()

fernet = Fernet(key)

# Decrypt each line
if not os.path.exists(ENC_FILE):
    print(f"[ERROR] Encrypted log file not found: {ENC_FILE}")
    exit(1)

os.makedirs(os.path.dirname(OUT_FILE), exist_ok=True)

with open(ENC_FILE, 'rb') as enc_f, open(OUT_FILE, 'w', encoding='utf-8') as out_f:
    for line in enc_f:
        try:
            decrypted = fernet.decrypt(line.strip())
            out_f.write(decrypted.decode() + "\n")
        except Exception as e:
            print(f"[WARN] Failed to decrypt line: {e}")
