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

# Load model and preprocessors
model = load_model(MODEL_PATH)
tokenizer = joblib.load(TOKENIZER_PATH)
label_encoder = joblib.load(LABEL_ENCODER_PATH)

# Load dataset
df = pd.read_parquet(PARQUET_PATH)

print("\n=== DATASET INFO ===")
print("Shape:", df.shape)
print("Columns:", df.columns.tolist())

# Use actual columns from your parquet
text_col = "full_session"
label_col = "Set_Fingerprint"

df = df[[text_col, label_col]].dropna().copy()
df[text_col] = df[text_col].astype(str).str.strip()
df[label_col] = df[label_col].astype(str).str.strip()

print("\nUnique raw labels in dataset:")
print(sorted(df[label_col].unique())[:20])

print("\nLabels known by model:")
print(list(label_encoder.classes_))

# Keep only labels that exist in the trained encoder
known_labels = set(label_encoder.classes_)
before_count = len(df)
df = df[df[label_col].isin(known_labels)].copy()
after_count = len(df)

print(f"\nRows before filtering: {before_count}")
print(f"Rows after filtering : {after_count}")

if len(df) == 0:
    raise ValueError("No rows left after filtering. Dataset labels do not match model label encoder.")

# Tokenize text
sequences = tokenizer.texts_to_sequences(df[text_col].tolist())
X = pad_sequences(sequences, maxlen=MAX_LEN)

# Encode labels
y_true = label_encoder.transform(df[label_col])

# Predict
y_pred_probs = model.predict(X, batch_size=64, verbose=1)
y_pred = np.argmax(y_pred_probs, axis=1)

# Metrics
print("\n=== LSTM RESULTS ===")
print("Accuracy:", accuracy_score(y_true, y_pred))

print("\n=== CLASSIFICATION REPORT ===")
print(classification_report(
    y_true,
    y_pred,
    target_names=label_encoder.classes_,
    digits=4
))

print("\n=== CONFUSION MATRIX ===")
print(confusion_matrix(y_true, y_pred))
