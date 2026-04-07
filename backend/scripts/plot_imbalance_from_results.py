from pathlib import Path
import re
import matplotlib.pyplot as plt


BASE_DIR = Path(__file__).resolve().parents[1]
FINAL_PROOF = BASE_DIR / "final_proof"

LSTM_RESULTS = FINAL_PROOF / "lstm_results.txt"
RF_RESULTS = FINAL_PROOF / "rf_results.txt"

SSH_OUT = FINAL_PROOF / "ssh_class_imbalance.png"
RF_OUT = FINAL_PROOF / "rf_class_imbalance.png"


def parse_counts_block(text: str, header: str) -> dict[str, int]:
    lines = text.splitlines()
    capture = False
    counts: dict[str, int] = {}

    for line in lines:
        stripped = line.strip()

        if stripped == header:
            capture = True
            continue

        if not capture:
            continue

        if not stripped:
            if counts:
                break
            continue

        if stripped.lower().startswith(("mapped_label", "label", "name:")):
            continue

        if stripped.startswith("==="):
            break

        match = re.match(r"^(.+?)\s+(\d+)$", stripped)
        if match:
            label = match.group(1).strip()
            value = int(match.group(2))
            counts[label] = value
        elif counts:
            break

    if not counts:
        raise ValueError(f"Could not parse block: {header}")

    return counts


def plot_bar(data: dict[str, int], title: str, outfile: Path) -> None:
    labels = list(data.keys())
    values = list(data.values())

    plt.figure(figsize=(10, 6))
    plt.bar(labels, values)
    plt.title(title)
    plt.xlabel("Class")
    plt.ylabel("Number of Samples")
    plt.xticks(rotation=20, ha="right")

    for i, v in enumerate(values):
        plt.text(i, v, str(v), ha="center", va="bottom", fontsize=9)

    plt.tight_layout()
    plt.savefig(outfile, dpi=220, bbox_inches="tight")
    plt.close()


def main() -> None:
    if not LSTM_RESULTS.exists():
        raise FileNotFoundError(f"Missing file: {LSTM_RESULTS}")
    if not RF_RESULTS.exists():
        raise FileNotFoundError(f"Missing file: {RF_RESULTS}")

    lstm_text = LSTM_RESULTS.read_text(encoding="utf-8", errors="ignore")
    rf_text = RF_RESULTS.read_text(encoding="utf-8", errors="ignore")

    ssh_counts = parse_counts_block(lstm_text, "=== MAPPED LABEL COUNTS ===")
    rf_counts = parse_counts_block(rf_text, "=== MAPPED TRUE LABEL COUNTS ===")

    plot_bar(
        ssh_counts,
        "SSH Behavioral Dataset Class Distribution",
        SSH_OUT,
    )
    plot_bar(
        rf_counts,
        "CICIoT RF Dataset Class Distribution",
        RF_OUT,
    )

    print("Saved:")
    print(SSH_OUT)
    print(RF_OUT)

    print("\nParsed SSH counts:")
    for k, v in ssh_counts.items():
        print(f"{k}: {v}")

    print("\nParsed RF counts:")
    for k, v in rf_counts.items():
        print(f"{k}: {v}")


if __name__ == "__main__":
    main()
