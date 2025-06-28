
## Rule-Based Detection 
- **Purpose**: Detects DNS tunneling using entropy (>3.5), query length (>50), and volume (>100 in 5 minutes).
- **Script**: `detector.py`
- **Features**:
  - Decrypts logs with AES-256 (`utils.py`).
  - Logs alerts to `logs/alerts.jsonl`.
  - Optimized with chunk processing (1000 lines/batch) for 2GB RAM.
  - Monitors CPU/memory with `psutil`.
- **Testing**: Validated with CICIDS 2027 dataset (`datasets/cicids_logs.jsonl`).
- **Performance**: Memory usage <50% on 2GB RAM VM.
##  ML Detection and Alerting
- **Tasks**:
  - Implemented `ml_detector.py` with Isolation Forest for DGA detection.
  - Integrated rule-based and ML detection in `detector.py`.
  - Added email alerts via SMTP.
  - Optimized ML for <50% CPU/memory on 2GB RAM.
- **Results**: Detected DGAs in synthetic data, alerts logged and emailed.
- **Next**:  Flask dashboard and SQLite storage.
### Dataset Integration (June 27)
- **Action**: Converted Friday-WorkingHours.pcap (8.2 GB) to datasets/cicids_logs.jsonl.
- **Results**: Integrated with detector.py and ml_detector.py, generating N rule-based and M ML alerts.
- **Next**: Optimize ML performance 
