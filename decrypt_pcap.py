# decrypt_pcap.py
from scapy.all import rdpcap, DNS, DNSQR
import json
import os

INPUT_PCAP = "dns_packets.pcap"
OUTPUT_JSONL = "datasets/cicids_logs.jsonl"

def process_pcap():
    if not os.path.exists(INPUT_PCAP):
        print(f"Error: {INPUT_PCAP} not found")
        return
    packets = rdpcap(INPUT_PCAP)
    alerts = []
    for pkt in packets:
        if DNS in pkt and pkt[DNS].qr == 0:  # Query packets
            timestamp = pkt.time
            domain = pkt[DNS].qd.qname.decode("utf-8").rstrip(".")
            alerts.append({
                "timestamp": int(timestamp),
                "domain": domain,
                "response_time": 0.0  # Placeholder; requires full handshake for real value
            })
    with open(OUTPUT_JSONL, 'w', encoding='utf-8') as f:
        for alert in alerts:
            f.write(json.dumps(alert) + '\n')

if __name__ == "__main__":
    process_pcap()
