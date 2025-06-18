## Rule-Based Detection (Week 2)
- **Purpose**: Detects DNS tunneling using entropy (>3.5), query length (>50), and volume (>100 in 5 minutes).
- **Script**: `detector.py`
- **Features**:
  - Decrypts logs with AES-256 (`utils.py`).
  - Logs alerts to `logs/alerts.jsonl`.
  - Optimized for 2GB RAM with chunk processing.
- **Testing**: Validated with CICIDS 2017 dataset.
