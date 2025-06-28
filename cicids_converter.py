import csv
import json
from cryptography.fernet import Fernet
from utils import load_key
import os

key = load_key()
fernet = Fernet(key)

output_file = "datasets/cicids_logs.jsonl"
input_file = "datasets/friday_dns_log.csv"

with open(output_file, "w", encoding="utf-8") as outfile:
    if not os.path.exists(input_file):
        print(f"Error: {input_file} not found")
        exit(1)
    with open(input_file, "r", encoding="utf-8") as csvfile:
        reader = csv.reader(csvfile)
        next(reader)  # Skip header if present
        for row in reader:
            if len(row) >= 4:  # Ensure all fields are present
                entry = {
                    "timestamp": float(row[0]) if row[0] else 0.0,
                    "src_ip": fernet.encrypt(row[1].encode()).decode(),
                    "dst_ip": fernet.encrypt(row[2].encode()).decode(),
                    "type": "query",
                    "query_name": fernet.encrypt(row[3].encode()).decode() if row[3] else fernet.encrypt("unknown.com".encode()).decode(),
                    "query_type": int(row[4]) if row[4].isdigit() else 1  # Default to A record
                }
                outfile.write(json.dumps(entry) + "\n")
print(f"Converted data written to {output_file}")
