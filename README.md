# DNS Security Project
This project implements a secure DNS logging and anomaly detection system for SMEs.

## Setup
- Install dependencies with `sudo apt install tshark tcpdump python3-pip python3-scapy git -y` and `pip3 install scikit-learn flask pandas`.
- Clone or manually add project files.

## Usage
- Run `decrypt_pcap.py` to generate dataset.
- Start with `python3 alert_server.py` and detection scripts.
