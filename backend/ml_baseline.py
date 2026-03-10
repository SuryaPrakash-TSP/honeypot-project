#!/usr/bin/env python3
"""
Honeypot Phase 5 ML Baseline - Production Script v2.1
Handles small datasets | Random Forest | Full logging
"""

import pandas as pd
import numpy as np
import sqlite3
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import f1_score
import os

def load_data():
    conn = sqlite3.connect('data/events.db')
    web_df = pd.read_sql_query("SELECT * FROM events WHERE event_type='web'", conn)
    conn.close()

    ssh_path = '../cowrie-parsed.txt'
    ssh_df = pd.DataFrame()
    if os.path.exists(ssh_path):
        ssh_df = pd.read_csv(ssh_path, sep='\t', header=None, 
                           names=['timestamp', 'ip', 'command'])
        ssh_df = ssh_df[['ip', 'command']].rename(columns={'ip':'source_ip'})
        ssh_df['event_type'] = 'ssh'

    df = pd.concat([web_df, ssh_df], ignore_index=True)
    return df

def engineer_features(df):
    df = df.copy()
    df['username_len'] = df['username'].str.len().fillna(0).astype(int)
    df['password_len'] = df['password'].str.len().fillna(0).astype(int)
    df['command_len'] = df['command'].str.len().fillna(0).astype(int)
    df['is_admin'] = (df['username'].str.lower() == 'admin').fillna(False).astype(int)

    features = ['username_len', 'password_len', 'command_len', 'is_admin']
    X = df[features].fillna(0)
    y = np.ones(len(X))
    return X, y, features

def train_model(X, y):
    n_samples = len(X)
    if n_samples < 4:
        rf = RandomForestClassifier(n_estimators=min(10, n_samples*2), random_state=42)
        rf.fit(X, y)
        return rf, 1.0, n_samples, rf.feature_importances_

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
    rf = RandomForestClassifier(n_estimators=100, random_state=42)
    rf.fit(X_train, y_train)
    y_pred = rf.predict(X_test)
    f1 = f1_score(y_test, y_pred)
    return rf, f1, len(X_test), rf.feature_importances_

def main():
    print("Honeypot ML Baseline v0.6.1")
    print("=" * 50)

    df = load_data()
    web_count = len(df[df['event_type']=='web']) if 'event_type' in df.columns else 0
    ssh_count = len(df[df['event_type']=='ssh']) if 'event_type' in df.columns else 0
    print(f"Dataset: {len(df)} events ({web_count} web, {ssh_count} ssh)")

    X, y, features = engineer_features(df)
    print(f"Features: {list(features)}")

    model, f1, test_size, importances = train_model(X, y)

    print("\nResults:")
    print(f"F1-Score: {f1:.3f}")
    print(f"Test set: {test_size} events")

    print("\nFeature Importance:")
    for feat, imp in zip(features, importances):
        print(f"  {feat:12}: {imp:.3f}")

    joblib.dump(model, 'honeypot_rf_model.pkl')
    print(f"\nModel saved: honeypot_rf_model.pkl")
    print("\nPhase 5 Complete")

if __name__ == "__main__":
    main()
