from cryptography.fernet import Fernet

KEY_FILE = "fernet.key"
ENC_FILE = "datasets/cicids_logs_encrypted.jsonl"
OUT_FILE = "datasets/cicids_logs.jsonl"

with open(KEY_FILE, 'rb') as f:
    key = f.read()

fernet = Fernet(key)

with open(ENC_FILE, 'rb') as enc_f:
    encrypted_lines = enc_f.readlines()

with open(OUT_FILE, 'w', encoding='utf-8') as out_f:
    for line in encrypted_lines:
        try:
            decrypted = fernet.decrypt(line.strip())
            out_f.write(decrypted.decode() + "\n")
        except Exception as e:
            print(f"Failed to decrypt line: {e}")
