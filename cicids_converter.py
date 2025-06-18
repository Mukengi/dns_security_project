# cicids_converter.py
import pandas as pd
import json
from utils import load_key, encrypt_data

def convert_cicids_to_jsonl(input_csv, output_jsonl):
    """Convert CICIDS 2017 CSV to JSON Lines format."""
    key = load_key()
    df = pd.read_csv(input_csv)
    with open(output_jsonl, "a") as f:
        for _, row in df.iterrows():
            log_entry = {
                "timestamp": row.get("Timestamp", 0.0),
                "src_ip": encrypt_data(row.get("Source IP", "0.0.0.0"), key),
                "dst_ip": encrypt_data(row.get("Destination IP", "0.0.0.0"), key),
                "type": "query",
                "query_name": encrypt_data(row.get("Query Name", ""), key),
                "query_type": row.get("Query Type", 1)
            }
            f.write(json.dumps(log_entry) + "\n")

if __name__ == "__main__":
    input_csv = "datasets/cicids_dns.csv"  # Adjust path
    output_jsonl = "datasets/cicids_logs.jsonl"
    convert_cicids_to_jsonl(input_csv, output_jsonl)
