# decrypt_test.py
import json
from utils import load_key, decrypt_data

key = load_key()
with open("logs/dns_logs.jsonl", "r") as f:
    for line in f:
        log_entry = json.loads(line)
        print("Decrypted Query Name:", decrypt_data(log_entry["query_name"], key))
        print("Decrypted Source IP:", decrypt_data(log_entry["src_ip"], key))
        print("Decrypted Destination IP:", decrypt_data(log_entry["dst_ip"], key))
        if log_entry.get("resp_data"):
            print("Decrypted Response Data:", decrypt_data(log_entry["resp_data"], key))
