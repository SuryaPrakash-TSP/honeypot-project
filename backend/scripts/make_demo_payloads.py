import json
import re
from pathlib import Path
from typing import Dict, Any, List, Set

import pandas as pd

DATASET_PATH = Path("~/honeypot-project/datasets/cicids2017/archive_intermediate/cicids2017_final.csv").expanduser()
OUTPUT_DIR = Path("~/honeypot-project/backend/final_proof/demo_payloads").expanduser()

LABEL_COLUMN = "Label"
CHUNK_SIZE = 50000

TARGET_CLASSES = [
    "BENIGN",
    "DDoS",
    "DoS Hulk",
    "DoS GoldenEye",
    "DoS slowloris",
    "DoS Slowhttptest",
    "FTP-Patator",
    "SSH-Patator",
    "PortScan",
    "Bot",
    "Web Attack - Brute Force",
    "Web Attack - XSS",
]

def safe_name(label: str) -> str:
    name = label.lower().strip()
    name = name.replace(" - ", "_")
    name = name.replace("-", "_")
    name = name.replace("/", "_")
    name = name.replace(" ", "_")
    name = re.sub(r"[^a-z0-9_]+", "", name)
    return name

def make_activity_text(label: str) -> str:
    mapping = {
        "BENIGN": "Normal network traffic pattern from CICIDS2017 sample",
        "DDoS": "Distributed denial of service traffic pattern detected",
        "DoS Hulk": "High-volume DoS Hulk traffic behavior detected",
        "DoS GoldenEye": "GoldenEye denial-of-service traffic signature detected",
        "DoS slowloris": "Slow connection exhaustion pattern detected",
        "DoS Slowhttptest": "Slow HTTP test attack behavior detected",
        "FTP-Patator": "FTP brute-force login attempt pattern detected",
        "SSH-Patator": "SSH brute-force login attempt pattern detected",
        "PortScan": "Multiple port probing activity detected",
        "Bot": "Botnet-like command and control traffic pattern detected",
        "Web Attack - Brute Force": "Web authentication brute-force pattern detected",
        "Web Attack - XSS": "Cross-site scripting web attack pattern detected",
    }
    return mapping.get(label, f"Suspicious network activity detected: {label}")

def make_ip(label: str, idx: int) -> str:
    base_map = {
        "BENIGN": 200,
        "DDoS": 201,
        "DoS Hulk": 202,
        "DoS GoldenEye": 203,
        "DoS slowloris": 204,
        "DoS Slowhttptest": 205,
        "FTP-Patator": 206,
        "SSH-Patator": 207,
        "PortScan": 208,
        "Bot": 209,
        "Web Attack - Brute Force": 210,
        "Web Attack - XSS": 211,
    }
    last = base_map.get(label, 250)
    return f"192.168.1.{last + idx}"

def build_payload(row: pd.Series, label: str, idx: int = 0, repeated_ip: str = None) -> Dict[str, Any]:
    features = {}
    for col, value in row.items():
        if col == LABEL_COLUMN:
            continue
        if pd.isna(value):
            value = 0
        if hasattr(value, "item"):
            value = value.item()
        features[col] = value

    safe_label = safe_name(label)
    ip = repeated_ip if repeated_ip else make_ip(label, idx)

    return {
        "ip": ip,
        "activity": make_activity_text(label),
        "session_id": f"demo-{safe_label}-{idx+1}",
        "event_type": "network",
        "features": features,
        "source_label": label
    }

def write_json(path: Path, payload: Dict[str, Any]) -> None:
    with open(path, "w") as f:
        json.dump(payload, f, indent=2)

def main():
    if not DATASET_PATH.exists():
        raise FileNotFoundError(f"Dataset not found: {DATASET_PATH}")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    found_payloads: Dict[str, Dict[str, Any]] = {}
    found_labels: Set[str] = set()

    repeated_targets = {"DDoS", "DoS Hulk", "SSH-Patator"}
    repeated_counts = {label: 0 for label in repeated_targets}
    repeat_ip = "192.168.1.250"

    created_files: List[Path] = []

    for chunk in pd.read_csv(DATASET_PATH, chunksize=CHUNK_SIZE):
        if LABEL_COLUMN not in chunk.columns:
            raise ValueError(f"Expected label column '{LABEL_COLUMN}' not found")

        chunk[LABEL_COLUMN] = chunk[LABEL_COLUMN].astype(str)
        found_labels.update(chunk[LABEL_COLUMN].dropna().unique().tolist())

        for label in TARGET_CLASSES:
            if label not in found_payloads:
                subset = chunk[chunk[LABEL_COLUMN] == label]
                if not subset.empty:
                    row = subset.iloc[0]
                    payload = build_payload(row, label, idx=0)
                    found_payloads[label] = payload

                    out_file = OUTPUT_DIR / f"{safe_name(label)}.json"
                    write_json(out_file, payload)
                    created_files.append(out_file)

        for label in repeated_targets:
            if repeated_counts[label] < 3:
                subset = chunk[chunk[LABEL_COLUMN] == label]
                if not subset.empty:
                    for _, row in subset.iterrows():
                        if repeated_counts[label] >= 3:
                            break
                        idx = repeated_counts[label]
                        payload = build_payload(row, label, idx=idx, repeated_ip=repeat_ip)
                        out_file = OUTPUT_DIR / f"{safe_name(label)}_repeat_{idx+1}.json"
                        write_json(out_file, payload)
                        created_files.append(out_file)
                        repeated_counts[label] += 1

        all_main_found = all(label in found_payloads for label in TARGET_CLASSES)
        all_repeats_done = all(repeated_counts[label] >= 3 for label in repeated_targets)

        if all_main_found and all_repeats_done:
            break

    print("Found labels in scanned chunks:")
    for label in sorted(found_labels):
        print(" -", label)

    missing_labels = [label for label in TARGET_CLASSES if label not in found_payloads]

    print("\nCreated payload files:")
    for file in sorted(created_files):
        print(file)

    if missing_labels:
        print("\nMissing labels:")
        for label in missing_labels:
            print(" -", label)
    else:
        print("\nAll target classes successfully generated.")

    print("\nRepeated payload counts:")
    for label, count in repeated_counts.items():
        print(f" - {label}: {count}")

if __name__ == "__main__":
    main()
