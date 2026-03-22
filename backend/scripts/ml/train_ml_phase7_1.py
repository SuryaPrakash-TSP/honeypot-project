#!/usr/bin/env python
import pandas as pd
import numpy as np
import joblib
import json
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
from sklearn.preprocessing import LabelEncoder
import os
import warnings
warnings.filterwarnings('ignore')

# Real dataset paths (no synthetic leaks)
DATA_PATHS = [
    'backend/data/events_full.csv',
    'backend/data/events_full_live.csv', 
    'backend/data/events_full_multi.csv',
    'backend/cowrie-events.json',
    'backend/data/features.csv'
]

def load_real_data():
    """Load and clean real honeypot data only"""
    all_data = []
    
    # CSV files
    for path in ['backend/data/events_full.csv', 'backend/data/events_full_live.csv', 
                'backend/data/events_full_multi.csv', 'backend/data/features.csv']:
        if os.path.exists(path):
            df = pd.read_csv(path)
            # Clean fake/synthetic indicators
            df = df[~df['ip'].str.contains('192.168.', na=False)]  # Remove local fake IPs
            df = df[~df['ip'].str.contains('10.', na=False)]
            df = df[df['label'].isin([0,1])]  # Only binary real labels
            all_data.append(df)
    
    # Cowrie JSON (if exists)
    if os.path.exists('backend/cowrie-events.json'):
        cowrie_df = pd.read_json('backend/cowrie-events.json')
        cowrie_df['label'] = 1  # Cowrie = attack
        all_data.append(cowrie_df[['cmd_len', 'sudo_flag', 'wget_curl', 'ip_freq', 'label']])
    
    if not all_data:
        raise ValueError("No real data found! Check backend/data/*.csv")
    
    df = pd.concat(all_data, ignore_index=True)
    print(f"Loaded {len(df)} real events after cleaning")
    return df.dropna()

def train_rf_v3(X, y):
    """Train RF v3 on cleaned real data"""
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    rf = RandomForestClassifier(n_estimators=200, max_depth=10, random_state=42, n_jobs=-1)
    rf.fit(X_train, y_train)
    
    # Predictions
    y_pred = rf.predict(X_test)
    y_proba = rf.predict_proba(X_test)[:, 1]
    
    # Metrics
    metrics = {
        'accuracy': accuracy_score(y_test, y_pred),
        'precision': precision_score(y_test, y_pred),
        'recall': recall_score(y_test, y_pred),
        'f1': f1_score(y_test, y_pred),
        'roc_auc': roc_auc_score(y_test, y_proba)
    }
    
    return rf, X_test, y_test, y_pred, metrics

def save_plots(rf, X_test, y_test, y_pred, metrics):
    """Generate confusion matrix + feature importance"""
    os.makedirs('backend/plots', exist_ok=True)
    
    # Confusion Matrix
    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                xticklabels=['Benign', 'Attack'], yticklabels=['Benign', 'Attack'])
    plt.title('RF v3 Confusion Matrix\nReal Honeypot Data')
    plt.ylabel('True'), plt.xlabel('Predicted')
    plt.savefig('backend/plots/confusion_matrix_v3.png', dpi=300, bbox_inches='tight')
    plt.close()
    
    # Feature Importance
    feat_imp = pd.DataFrame({
        'feature': ['cmd_len', 'sudo_flag', 'wget_curl', 'ip_freq'],
        'importance': rf.feature_importances_
    }).sort_values('importance', ascending=True)
    
    plt.figure(figsize=(10, 6))
    sns.barplot(data=feat_imp, x='importance', y='feature')
    plt.title('RF v3 Feature Importance\nReal Honeypot Data')
    plt.xlabel('Importance Score')
    for i, v in enumerate(feat_imp['importance']):
        plt.text(v + 0.001, i, f'{v:.3f}', va='center')
    plt.savefig('backend/plots/feature_importance_v3.png', dpi=300, bbox_inches='tight')
    plt.close()

def save_model_info(rf, metrics, X_shape):
    """Save model metadata"""
    model_info = {
        "model_version": "honeypot_rf_v3",
        "trained_on": "2026-03-22",
        "dataset_sources": ["events_full.csv", "events_full_live.csv", "events_full_multi.csv", "cowrie-events.json"],
        "dataset_size": X_shape[0],
        "features": ["cmd_len", "sudo_flag", "wget_curl", "ip_freq"],
        "accuracy": round(metrics['accuracy'], 4),
        "precision": round(metrics['precision'], 4),
        "recall": round(metrics['recall'], 4),
        "f1": round(metrics['f1'], 4),
        "roc_auc": round(metrics['roc_auc'], 4),
        "license": "MIT",
        "limitations": "Binary classification only, real honeypot data, no zero-day detection"
    }
    
    with open('backend/data/model_info_v3.json', 'w') as f:
        json.dump(model_info, f, indent=2)
    print("Saved model_info_v3.json")

if __name__ == "__main__":
    print("🚀 Phase 7.1: Training honeypot_rf_v3 on real data...")
    
    # Load & prepare
    df = load_real_data()
    FEATURES = ['cmd_len', 'sudo_flag', 'wget_curl', 'ip_freq']
    X = df[FEATURES].values
    y = df['label'].values
    
    # Train
    rf, X_test, y_test, y_pred, metrics = train_rf_v3(X, y)
    
    # Save model
    joblib.dump(rf, 'backend/app/honeypot_rf_v3.pkl')
    
    # Plots & metrics
    save_plots(rf, X_test, y_test, y_pred, metrics)
    save_model_info(rf, metrics, X.shape)
    
    print("\n✅ SUCCESS! Generated:")
    print("- backend/app/honeypot_rf_v3.pkl")
    print("- backend/plots/confusion_matrix_v3.png") 
    print("- backend/plots/feature_importance_v3.png")
    print("- backend/data/model_info_v3.json")
    print(f"Real Metrics: {metrics}")
