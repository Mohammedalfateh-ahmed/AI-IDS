"""
PROPER IDS Model Training
Uses SEPARATE train and test datasets for REAL accuracy
Train: NSL-KDD.csv
Test: NSL-KDD_test.csv (completely different data)
"""

import pandas as pd
import numpy as np
import joblib
import json
import os
from datetime import datetime

from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report
from xgboost import XGBClassifier

print("="*60)
print("PROPER IDS MODEL TRAINING")
print("Using SEPARATE train and test datasets")
print("="*60)

ATTACK_MAPPING = {
    'normal': 'Normal',
    'neptune': 'DoS', 'smurf': 'DoS', 'pod': 'DoS', 'teardrop': 'DoS',
    'land': 'DoS', 'back': 'DoS', 'apache2': 'DoS', 'udpstorm': 'DoS',
    'processtable': 'DoS', 'mailbomb': 'DoS',
    'portsweep': 'Probe', 'ipsweep': 'Probe', 'satan': 'Probe', 'nmap': 'Probe',
    'mscan': 'Probe', 'saint': 'Probe',
    'guess_passwd': 'R2L', 'ftp_write': 'R2L', 'imap': 'R2L', 'phf': 'R2L',
    'multihop': 'R2L', 'warezmaster': 'R2L', 'warezclient': 'R2L', 'spy': 'R2L',
    'xlock': 'R2L', 'xsnoop': 'R2L', 'snmpguess': 'R2L', 'snmpgetattack': 'R2L',
    'httptunnel': 'R2L', 'sendmail': 'R2L', 'named': 'R2L', 'worm': 'R2L',
    'buffer_overflow': 'U2R', 'loadmodule': 'U2R', 'rootkit': 'U2R', 'perl': 'U2R',
    'sqlattack': 'U2R', 'xterm': 'U2R', 'ps': 'U2R'
}

print("\n[1/6] Loading TRAINING data (NSL-KDD.csv)...")
df_train = pd.read_csv('data/raw/NSL-KDD.csv')
print(f"      Training samples: {len(df_train):,}")

print("\n[2/6] Loading TEST data (NSL-KDD_test.csv)...")
df_test = pd.read_csv('data/raw/NSL-KDD_test.csv')
print(f"      Test samples: {len(df_test):,}")

print("\n[3/6] Processing labels...")

df_train['attack_category'] = df_train['label'].str.lower().str.strip().map(ATTACK_MAPPING)
df_train = df_train[df_train['attack_category'].notna()]

df_test['attack_category'] = df_test['label'].str.lower().str.strip().map(ATTACK_MAPPING)
df_test = df_test[df_test['attack_category'].notna()]

print(f"\n      Training Distribution:")
for cat, count in df_train['attack_category'].value_counts().items():
    print(f"        {cat:8s}: {count:6,}")

print(f"\n      Test Distribution:")
for cat, count in df_test['attack_category'].value_counts().items():
    print(f"        {cat:8s}: {count:6,}")

print("\n[4/6] Preparing features...")

categorical_cols = ['protocol_type', 'service', 'flag']

df_train_encoded = pd.get_dummies(df_train, columns=categorical_cols, drop_first=False)
df_test_encoded = pd.get_dummies(df_test, columns=categorical_cols, drop_first=False)

train_cols = set(df_train_encoded.columns)
test_cols = set(df_test_encoded.columns)

for col in train_cols - test_cols:
    if col not in ['label', 'attack_category', 'difficulty']:
        df_test_encoded[col] = 0

for col in test_cols - train_cols:
    if col not in ['label', 'attack_category', 'difficulty']:
        df_train_encoded[col] = 0

drop_cols = ['label', 'attack_category', 'difficulty']
feature_cols = [c for c in df_train_encoded.columns if c not in drop_cols]
feature_cols = sorted(feature_cols)

X_train = df_train_encoded[feature_cols]
y_train = df_train['attack_category']

X_test = df_test_encoded[feature_cols]
y_test = df_test['attack_category']

print(f"      Features: {len(feature_cols)}")

print("\n[5/6] Training XGBoost model...")

label_encoder = LabelEncoder()
label_encoder.fit(list(set(y_train.unique()) | set(y_test.unique())))
y_train_encoded = label_encoder.transform(y_train)
y_test_encoded = label_encoder.transform(y_test)

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

model = XGBClassifier(
    n_estimators=200,
    max_depth=10,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    objective='multi:softprob',
    num_class=len(label_encoder.classes_),
    random_state=42,
    n_jobs=-1,
    verbosity=0
)

print("      Training in progress...")
model.fit(X_train_scaled, y_train_encoded)
print("      Done!")

print("\n[6/6] Evaluating on SEPARATE TEST DATA...")
y_pred = model.predict(X_test_scaled)

accuracy = accuracy_score(y_test_encoded, y_pred)
precision = precision_score(y_test_encoded, y_pred, average='weighted', zero_division=0)
recall = recall_score(y_test_encoded, y_pred, average='weighted', zero_division=0)
f1 = f1_score(y_test_encoded, y_pred, average='weighted', zero_division=0)

print("\n" + "="*60)
print("REAL MODEL PERFORMANCE")
print("(Tested on completely separate data)")
print("="*60)
print(f"      Accuracy:  {accuracy*100:.2f}%")
print(f"      Precision: {precision*100:.2f}%")
print(f"      Recall:    {recall*100:.2f}%")
print(f"      F1 Score:  {f1*100:.2f}%")

print("\n      Per-Class Performance:")
print("-"*60)
print(classification_report(y_test_encoded, y_pred, target_names=label_encoder.classes_, zero_division=0))

print("\n" + "="*60)
print("SAVING MODEL")
print("="*60)

output_dir = 'backend/data/models'
os.makedirs(output_dir, exist_ok=True)

joblib.dump(model, os.path.join(output_dir, 'xgboost_nslkdd_model.pkl'))
print("      ✓ Model saved")

preprocessor_data = {
    'scaler': scaler,
    'label_encoder': label_encoder,
    'feature_names': feature_cols
}
joblib.dump(preprocessor_data, os.path.join(output_dir, 'preprocessor_nslkdd.pkl'))
print("      ✓ Preprocessor saved")

metrics_data = {
    'model_name': 'XGBoost NSL-KDD',
    'training_date': datetime.now().isoformat(),
    'accuracy': round(float(accuracy), 4),
    'precision': round(float(precision), 4),
    'recall': round(float(recall), 4),
    'f1_score': round(float(f1), 4),
    'features': len(feature_cols),
    'classes': list(label_encoder.classes_),
    'training_samples': len(X_train),
    'test_samples': len(X_test),
    'training_dataset': 'NSL-KDD (KDDTrain+)',
    'test_dataset': 'NSL-KDD (KDDTest+)',
    'note': 'Proper evaluation using separate train/test datasets'
}

with open(os.path.join(output_dir, 'model_metrics.json'), 'w') as f:
    json.dump(metrics_data, f, indent=2)
print("      ✓ Metrics saved")

print("\n" + "="*60)
print("TRAINING COMPLETE!")
print("="*60)
print(f"\n      This is the REAL accuracy of your model.")
print(f"      Tested on {len(X_test):,} completely unseen samples.")
print(f"\n      Restart backend to use new model!")
print("="*60)