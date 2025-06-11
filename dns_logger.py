# dns_logger.py
import json
from scapy.all import sniff, DNS, DNSQR, DNSRR
from config import INTERFACE, LOG_FILE
from utils import hash_data, load_key, encrypt_data

key = load_key()
previous_hash = None

def packet_callback(packet):
    """Process, hash, encrypt, and log DNS packets."""
    global previous_hash
    try:
        if packet.haslayer(DNS):
            dns = packet[DNS]
            log_entry = {
                "timestamp": packet.time
            }
            unencrypted_log = {
                "timestamp": packet.time,
                "src_ip": packet[0].src,
                "dst_ip": packet[0].dst
            }
            if dns.qr == 0:  # Query
                log_entry["type"] = "query"
                query_name = dns[DNSQR].qname.decode('utf-8', errors='ignore')
                try:
                    log_entry["query_name"] = encrypt_data(query_name, key)
                except Exception as e:
                    print(f"Encryption error for query_name: {e}")
                    return
                log_entry["query_type"] = dns[DNSQR].qtype
                try:
                    log_entry["src_ip"] = encrypt_data(packet[0].src, key)
                    log_entry["dst_ip"] = encrypt_data(packet[0].dst, key)
                except Exception as e:
                    print(f"Encryption error for IPs: {e}")
                    return
                unencrypted_log.update({
                    "type": "query",
                    "query_name": query_name,
                    "query_type": dns[DNSQR].qtype
                })
            elif dns.qr == 1:  # Response
                log_entry["type"] = "response"
                query_name = dns[DNSQR].qname.decode('utf-8', errors='ignore')
                try:
                    log_entry["query_name"] = encrypt_data(query_name, key)
                except Exception as e:
                    print(f"Encryption error for query_name: {e}")
                    return
                rdata = dns[DNSRR].rdata if dns.an else None
                rdata_str = rdata.decode('utf-8', errors='ignore') if isinstance(rdata, bytes) else str(rdata) if rdata else None
                if rdata_str:
                    try:
                        log_entry["resp_data"] = encrypt_data(rdata_str, key)
                    except Exception as e:
                        print(f"Encryption error for resp_data: {e}")
                        return
                else:
                    log_entry["resp_data"] = None
                try:
                    log_entry["src_ip"] = encrypt_data(packet[0].src, key)
                    log_entry["dst_ip"] = encrypt_data(packet[0].dst, key)
                except Exception as e:
                    print(f"Encryption error for IPs: {e}")
                    return
                unencrypted_log.update({
                    "type": "response",
                    "query_name": query_name,
                    "resp_data": rdata_str
                })
            
            # Hash unencrypted log
            log_str = json.dumps(unencrypted_log, sort_keys=True)
            log_entry["hash"] = hash_data(log_str)
            log_entry["previous_hash"] = previous_hash
            previous_hash = log_entry["hash"]
            
            with open(LOG_FILE, "a") as f:
                f.write(json.dumps(log_entry) + "\n")
    except Exception as e:
        print(f"Error processing packet: {e}")

if __name__ == "__main__":
    print(f"Starting DNS logging on {INTERFACE}...")
    try:
        sniff(iface=INTERFACE, filter="udp port 53", prn=packet_callback, store=0)
    except Exception as e:
        print(f"Error in packet capture: {e}")
