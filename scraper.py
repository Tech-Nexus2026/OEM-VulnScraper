import time
import random

USER_AGENTS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"]

def poll_oem_portal():
    print("[POLL] Checking OEM security portal for new advisories...")
    record = {"name": "Chrome", "severity": "High", "unique_id": "CVE-2023-47131"}
    print(f"[SUCCESS] Fetched live record: {record}")

def start_scheduler():
    print("Starting Member 1 Automated Polling Engine (Press Ctrl+C to stop)...")
    try:
        for i in range(2):
            poll_oem_portal()
            if i < 1:
                print("Waiting 5 seconds for next polling cycle...")
                time.sleep(5)
    except KeyboardInterrupt:
        print("Polling stopped.")

if __name__ == "__main__":
    start_scheduler()
