# generate_logs.py

import json
import random
import time
import os
from cryptography.fernet import Fernet
from utils import load_key

LOG_FILE = "logs/dns_logs.jsonl"
os.makedirs("logs", exist_ok=True)

benign_domains = [
    "www.google.com", "strathmore.edu", "facebook.com",
    "github.com", "openai.com", "bbc.co.uk"
]

dga_like_domains = [
    "xj3kz2qo9.com", "a9f3zj4l.biz", "mkpq839.net",
    "zlxmnvasd.org", "q9w8e7r6t5.com", "yxzlo998.biz"
]

def encrypt_domain(domain, fernet):
    return fernet.encrypt(domain.encode()).decode()

def generate_log_entry(fernet, domain, ts):
    return {
        "timestamp": ts,
        "type": "query",
        "query_name": encrypt_domain(domain, fernet)
    }

def generate_logs():
    key = load_key()
    fernet = Fernet(key)
    entries = []

    now = int(time.time())
    for i in range(30):
        ts = now + i * 5
        domain = random.choice(benign_domains if i % 3 != 0 else dga_like_domains)
        entry = generate_log_entry(fernet, domain, ts)
        entries.append(entry)

    with open(LOG_FILE, "w", encoding="utf-8") as f:
        for entry in entries:
            f.write(json.dumps(entry) + "\n")

    print(f"Generated {len(entries)} sample DNS queries at {LOG_FILE}")

if __name__ == "__main__":
    generate_logs()
