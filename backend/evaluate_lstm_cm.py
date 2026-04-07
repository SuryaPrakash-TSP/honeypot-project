import json
import numpy as np
import pandas as pd
import joblib
import matplotlib.pyplot as plt

from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences
from sklearn.metrics import (
    confusion_matrix,
    ConfusionMatrixDisplay,
    classification_report,
    accuracy_score,
    precision_recall_fscore_support,
)

PARQUET_PATH = "data/datasets/ssh-shell/ssh_attacks.parquet"
MODEL_PATH = "app/lstm_ssh_v9.keras"
TOKENIZER_PATH = "app/lstm_tokenizer.pkl"
LABEL_ENCODER_PATH = "app/lstm_label_encoder.pkl"
METADATA_PATH = "app/lstm_metadata.json"
MAX_LEN = 50

with open(METADATA_PATH, "r") as f:
    metadata = json.load(f)

label_mapping = metadata["label_mapping"]

model = load_model(MODEL_PATH)
tokenizer = joblib.load(TOKENIZER_PATH)
label_encoder = joblib.load(LABEL_ENCODER_PATH)


def map_fingerprint(fingerprint):
    if isinstance(fingerprint, np.ndarray):
        tactics = {str(x).strip() for x in fingerprint.tolist()}
    elif isinstance(fingerprint, (list, tuple, set)):
        tactics = {str(x).strip() for x in fingerprint}
    else:
        tactics = {str(fingerprint).strip()}

    if "Execution" in tactics:
        return label_mapping["Execution"]
    elif "Persistence" in tactics:
        return label_mapping["Persistence"]
    elif "Discovery" in tactics:
        return label_mapping["Discovery"]
    elif "Harmless" in tactics:
        return label_mapping["Harmless"]
    else:
        return label_mapping["fallback"]


df = pd.read_parquet(PARQUET_PATH)[["full_session", "Set_Fingerprint"]].dropna().copy()
df["full_session"] = df["full_session"].astype(str).str.lower().str.strip()
df["mapped_label"] = df["Set_Fingerprint"].apply(map_fingerprint)

print("\n=== MAPPED LABEL COUNTS ===")
print(df["mapped_label"].value_counts())

known = set(label_encoder.classes_)
df = df[df["mapped_label"].isin(known)].copy()

print("\n=== MODEL CLASSES ===")
print(list(label_encoder.classes_))
print(f"Rows used for evaluation: {len(df)}")

X_seq = tokenizer.texts_to_sequences(df["full_session"].tolist())
X = pad_sequences(X_seq, maxlen=MAX_LEN, padding="post", truncating="post")

y_true = label_encoder.transform(df["mapped_label"])
y_pred_probs = model.predict(X, batch_size=64, verbose=1)
y_pred = np.argmax(y_pred_probs, axis=1)

acc = accuracy_score(y_true, y_pred)
prec, rec, f1, _ = precision_recall_fscore_support(
    y_true, y_pred, average="weighted", zero_division=0
)

print("\n=== LSTM METRICS ===")
print(f"Accuracy : {acc:.4f}")
print(f"Precision: {prec:.4f}")
print(f"Recall   : {rec:.4f}")
print(f"F1-score : {f1:.4f}")

print("\n=== CLASSIFICATION REPORT ===")
print(classification_report(
    y_true,
    y_pred,
    target_names=label_encoder.classes_,
    digits=4,
    zero_division=0
))

cm = confusion_matrix(y_true, y_pred)

print("\n=== CONFUSION MATRIX ===")
print(cm)

disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=label_encoder.classes_)
fig, ax = plt.subplots(figsize=(8, 6))
disp.plot(ax=ax, values_format="d")
plt.title("LSTM Confusion Matrix")
plt.tight_layout()
plt.savefig("lstm_confusion_matrix.png", dpi=200)

print("\nSaved image: lstm_confusion_matrix.png")
