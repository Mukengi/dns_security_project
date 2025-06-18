## Rule-Based Detection (Week 6)
- **Purpose**: Detects DNS tunneling using entropy (>3.5), query length (>50), and volume (>100 in 5 minutes).
- **Script**: `detector.py`
- **Features**:
  - Decrypts logs with AES-256 (`utils.py`).
  - Logs alerts to `logs/alerts.jsonl`.
  - Optimized with chunk processing (1000 lines/batch) for 2GB RAM.
  - Monitors CPU/memory with `psutil`.
- **Testing**: Validated with CICIDS 2027 dataset (`datasets/cicids_logs.jsonl`).
- **Performance**: Memory usage <50% on 2GB RAM VM.
