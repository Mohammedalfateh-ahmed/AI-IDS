import joblib
import pandas as pd
import numpy as np
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report
import json
import os

print("="*60)
print("EVALUATING YOUR REAL MODEL")
print("="*60)

print("\n1. Loading model and preprocessor...")
try:
    model = joblib.load('../data/models/xgboost_nslkdd_model.pkl')
    print("✅ Model loaded successfully")
except:
    model = joblib.load('data/models/xgboost_nslkdd_model.pkl')

try:
    preprocessor = joblib.load('../data/models/preprocessor_nslkdd.pkl')
    print(f"✅ Preprocessor loaded (type: {type(preprocessor).__name__})")
except:
    preprocessor = joblib.load('data/models/preprocessor_nslkdd.pkl')

scaler = preprocessor['scaler']
label_encoder = preprocessor['label_encoder']
expected_features = preprocessor['feature_names']

print(f"Expected features: {len(expected_features)}")

print("\n2. Loading test dataset...")
try:
    test_df = pd.read_csv('../data/raw/NSL-KDD_test.csv')
except:
    test_df = pd.read_csv('data/raw/NSL-KDD_test.csv')

print(f"✅ Loaded {len(test_df)} test samples")

print("\n3. Preparing and encoding data...")

if 'label' in test_df.columns:
    y_test = test_df['label']
    X_test = test_df.drop('label', axis=1)
elif 'class' in test_df.columns:
    y_test = test_df['class']
    X_test = test_df.drop('class', axis=1)
else:
    y_test = test_df.iloc[:, -1]
    X_test = test_df.iloc[:, :-1]

if 'difficulty' in X_test.columns:
    X_test = X_test.drop('difficulty', axis=1)
    print("Dropped 'difficulty' column")

print(f"Raw features: {X_test.shape[1]}")

categorical_columns = ['protocol_type', 'service', 'flag']
numerical_columns = [col for col in X_test.columns if col not in categorical_columns]

print(f"Categorical columns: {categorical_columns}")
print(f"Numerical columns: {len(numerical_columns)}")

X_test_encoded = pd.get_dummies(X_test, columns=categorical_columns)
print(f"After encoding: {X_test_encoded.shape[1]} features")

missing_cols = set(expected_features) - set(X_test_encoded.columns)
for col in missing_cols:
    X_test_encoded[col] = 0

extra_cols = set(X_test_encoded.columns) - set(expected_features)
X_test_encoded = X_test_encoded.drop(columns=extra_cols)

X_test_encoded = X_test_encoded[expected_features]
print(f"Aligned to expected features: {X_test_encoded.shape[1]}")

print("\n4. Scaling features...")
X_test_scaled = scaler.transform(X_test_encoded)
print("✅ Data preprocessed successfully")

print("\n5. Making predictions...")
y_pred_numeric = model.predict(X_test_scaled)
print("✅ Predictions complete")

print("\n6. Decoding predictions to labels...")
try:
    y_pred_labels = label_encoder.inverse_transform(y_pred_numeric.astype(int))
    print(f"✅ Decoded {len(y_pred_labels)} predictions")
    print(f"Sample predictions: {y_pred_labels[:5]}")
except Exception as e:
    print(f"⚠️ Decoding error: {e}")
    print("Using numeric predictions directly")
    y_pred_labels = y_pred_numeric

print("\n" + "="*60)
print("YOUR REAL MODEL PERFORMANCE")
print("="*60)

accuracy = accuracy_score(y_test, y_pred_labels)
precision = precision_score(y_test, y_pred_labels, average='weighted', zero_division=0)
recall = recall_score(y_test, y_pred_labels, average='weighted', zero_division=0)
f1 = f1_score(y_test, y_pred_labels, average='weighted', zero_division=0)

print(f"\n📊 Overall Metrics:")
print(f"   Accuracy:  {accuracy*100:.2f}%")
print(f"   Precision: {precision*100:.2f}%")
print(f"   Recall:    {recall*100:.2f}%")
print(f"   F1-Score:  {f1*100:.2f}%")

unique_classes = sorted(y_test.unique())
print(f"\n🎯 Attack Classes: {len(unique_classes)}")
print("\nDetailed breakdown:")
for cls in unique_classes:
    count_actual = sum(y_test == cls)
    count_pred = sum(y_pred_labels == cls)
    correct = sum((y_test == cls) & (y_pred_labels == cls))
    class_accuracy = (correct / count_actual * 100) if count_actual > 0 else 0
    print(f"   {cls:20s}: {count_actual:5d} actual | {count_pred:5d} predicted | {class_accuracy:5.1f}% accuracy")

print("\n📋 Detailed Classification Report:")
print(classification_report(y_test, y_pred_labels, zero_division=0))

metrics = {
    "accuracy": float(accuracy),
    "precision": float(precision),
    "recall": float(recall),
    "f1_score": float(f1),
    "attack_classes": [str(c) for c in unique_classes],
    "model_name": "XGBoost NSL-KDD Classifier",
    "training_dataset": "NSL-KDD Dataset",
    "test_samples": len(test_df),
    "features": len(expected_features)
}

try:
    os.makedirs('../data/models', exist_ok=True)
    with open('../data/models/model_metrics.json', 'w') as f:
        json.dump(metrics, f, indent=2)
    print("\n✅ Real metrics saved to: ../data/models/model_metrics.json")
except:
    os.makedirs('data/models', exist_ok=True)
    with open('data/models/model_metrics.json', 'w') as f:
        json.dump(metrics, f, indent=2)
    print("\n✅ Real metrics saved to: data/models/model_metrics.json")

print("\n" + "="*60)
print("🎓 THESE ARE YOUR REAL GRADUATION PROJECT METRICS!")
print("="*60)
print("\n✅ What to do next:")
print("   1. Use these metrics in your thesis/presentation")
print("   2. Restart your backend to load real metrics")
print("   3. Your dashboard will now show REAL performance!")
print("\n🚀 Run: python -m app.main")
print("="*60)