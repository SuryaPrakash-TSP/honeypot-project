import pandas as pd
import numpy as np
import joblib

from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

PARQUET_PATH = "data/datasets/ssh-shell/ssh_attacks.parquet"
MODEL_PATH = "app/lstm_ssh_v9.keras"
TOKENIZER_PATH = "app/lstm_tokenizer.pkl"
LABEL_ENCODER_PATH = "app/lstm_label_encoder.pkl"
MAX_LEN = 50


def map_label(fingerprint):
    if isinstance(fingerprint, np.ndarray):
        labels = {str(x).strip() for x in fingerprint.tolist()}
    elif isinstance(fingerprint, (list, tuple, set)):
        labels = {str(x).strip() for x in fingerprint}
    else:
        labels = {str(fingerprint).strip()}

    if "Execution" in labels:
        return "exploitation"
    elif "Persistence" in labels:
        return "privilege_abuse"
    elif "Discovery" in labels:
        return "reconnaissance"
    elif "Harmless" in labels:
        return "normal"
    else:
        return "other"


model = load_model(MODEL_PATH)
tokenizer = joblib.load(TOKENIZER_PATH)
label_encoder = joblib.load(LABEL_ENCODER_PATH)

df = pd.read_parquet(PARQUET_PATH)

print("\n=== DATASET INFO ===")
print("Shape:", df.shape)
print("Columns:", df.columns.tolist())

text_col = "full_session"
raw_label_col = "Set_Fingerprint"

df = df[[text_col, raw_label_col]].dropna().copy()
df[text_col] = df[text_col].astype(str).str.lower().str.strip()
df["mapped_label"] = df[raw_label_col].apply(map_label)

print("\nMapped label distribution:")
print(df["mapped_label"].value_counts())

print("\nLabels known by model:")
print(list(label_encoder.classes_))

known_labels = set(label_encoder.classes_)
before_count = len(df)
df = df[df["mapped_label"].isin(known_labels)].copy()
after_count = len(df)

print(f"\nRows before filtering: {before_count}")
print(f"Rows after filtering : {after_count}")

if len(df) == 0:
    raise ValueError("No rows left after filtering after mapped_label conversion.")

sequences = tokenizer.texts_to_sequences(df[text_col].tolist())
X = pad_sequences(sequences, maxlen=MAX_LEN, padding="post", truncating="post")

y_true = label_encoder.transform(df["mapped_label"])

y_pred_probs = model.predict(X, batch_size=64, verbose=1)
y_pred = np.argmax(y_pred_probs, axis=1)

print("\n=== LSTM RESULTS ===")
print("Accuracy:", accuracy_score(y_true, y_pred))

print("\n=== CLASSIFICATION REPORT ===")
print(classification_report(
    y_true,
    y_pred,
    target_names=label_encoder.classes_,
    digits=4,
    zero_division=0
))

print("\n=== CONFUSION MATRIX ===")
print(confusion_matrix(y_true, y_pred))
