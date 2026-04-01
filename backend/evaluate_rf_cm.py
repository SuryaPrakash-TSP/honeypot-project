import joblib
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay,
    precision_recall_fscore_support,
)

MODEL_PATH = "app/ciciot_rf_model.pkl"
COLUMNS_PATH = "app/ciciot_feature_columns.pkl"
DATA_PATH = "../datasets/ciciot_data/CICIOT23/train/train.csv"


def map_label(label):
    label = str(label).strip()

    if "DDoS" in label:
        return "DDoS"
    elif label.startswith("DoS") or "DoS-" in label:
        return "DoS"
    elif "Mirai" in label:
        return "Mirai"
    elif "Recon" in label or "VulnerabilityScan" in label:
        return "Recon"
    elif "Benign" in label:
        return "Benign"
    elif (
        "Spoof" in label
        or "BruteForce" in label
        or "Injection" in label
        or "XSS" in label
        or "Backdoor" in label
        or "BrowserHijacking" in label
        or "Uploading_Attack" in label
        or "MITM" in label
    ):
        return "Other"
    else:
        return "Other"


model = joblib.load(MODEL_PATH)
feature_columns = joblib.load(COLUMNS_PATH)

print("Loaded feature count:", len(feature_columns))

# Read a manageable sample
df = pd.read_csv(DATA_PATH, nrows=50000)
print("Original shape:", df.shape)

# Detect label column
possible_label_cols = ["label", "Label", "attack", "Attack", "class"]
label_col = None
for c in possible_label_cols:
    if c in df.columns:
        label_col = c
        break

if label_col is None:
    raise ValueError(f"Could not find label column. Available columns: {df.columns.tolist()}")

print("Using label column:", label_col)

# Keep only rows with all required features
missing_features = [c for c in feature_columns if c not in df.columns]
if missing_features:
    raise ValueError(f"Missing required features: {missing_features}")

df = df[feature_columns + [label_col]].dropna().copy()
print("Filtered shape:", df.shape)

X = df[feature_columns]

# Map raw dataset labels to coarse training/evaluation classes
y_true_raw = df[label_col].astype(str)
y_true = y_true_raw.apply(map_label)

# Predict and map model outputs to same coarse classes
y_pred_raw = pd.Series(model.predict(X), index=df.index).astype(str)
y_pred = y_pred_raw.apply(map_label)

print("\n=== MAPPED TRUE LABEL COUNTS ===")
print(y_true.value_counts())

print("\n=== MAPPED PREDICTED LABEL COUNTS ===")
print(y_pred.value_counts())

acc = accuracy_score(y_true, y_pred)
prec, rec, f1, _ = precision_recall_fscore_support(
    y_true, y_pred, average="weighted", zero_division=0
)

print("\n=== RF METRICS ===")
print(f"Accuracy : {acc:.4f}")
print(f"Precision: {prec:.4f}")
print(f"Recall   : {rec:.4f}")
print(f"F1-score : {f1:.4f}")

labels = ["Benign", "DDoS", "DoS", "Mirai", "Recon", "Other"]

print("\n=== CLASSIFICATION REPORT ===")
print(classification_report(y_true, y_pred, labels=labels, digits=4, zero_division=0))

cm = confusion_matrix(y_true, y_pred, labels=labels)

print("\n=== CONFUSION MATRIX ===")
print(cm)

fig, ax = plt.subplots(figsize=(10, 8))
disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=labels)
disp.plot(ax=ax, xticks_rotation=30, values_format="d")
plt.title("CICIoT Random Forest Confusion Matrix")
plt.tight_layout()
plt.savefig("rf_confusion_matrix.png", dpi=200)

print("\nSaved image: rf_confusion_matrix.png")
