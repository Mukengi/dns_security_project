from scapy.all import rdpcap, DNS, DNSQR
import json
import os
from cryptography.fernet import Fernet

INPUT_PCAP = "dns_packets.pcap"
OUTPUT_JSONL = "datasets/cicids_logs.jsonl"

# Generate a key for AES-256 (store securely in production)
key = Fernet.generate_key()
cipher_suite = Fernet(key)

def process_pcap():
    if not os.path.exists(INPUT_PCAP):
        print(f"Error: {INPUT_PCAP} not found")
        return
    try:
        packets = rdpcap(INPUT_PCAP)
        alerts = []
        for pkt in packets:
            try:
                if DNS in pkt and pkt[DNS].qr == 0:  # Query packets
                    timestamp = int(pkt.time) if 'time' in pkt.fields else 0
                    domain = pkt[DNS].qd.qname.decode("utf-8", errors='ignore').rstrip(".") if 'qd' in pkt[DNS].fields and pkt[DNS].qd else "unknown"
                    response_time = float(pkt.time) if 'time' in pkt.fields else 0.0
                    alerts.append({
                        "timestamp": timestamp,
                        "domain": domain,
                        "response_time": response_time
                    })
            except Exception as e:
                print(f"Skipped packet due to error: {e}")
        with open(OUTPUT_JSONL, 'w', encoding='utf-8') as f:
            for alert in alerts:
                f.write(json.dumps(alert, ensure_ascii=False) + '\n')
    except Exception as e:
        print(f"Processing error: {e}")

if __name__ == "__main__":
    process_pcap()
