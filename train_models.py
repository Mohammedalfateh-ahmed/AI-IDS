import sys
import os
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
import joblib
import warnings
warnings.filterwarnings('ignore')

from sklearn.metrics import (
    classification_report, 
    confusion_matrix, 
    accuracy_score,
    precision_score,
    recall_score,
    f1_score
)
import xgboost as xgb

sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))
from backend.app.ml.preprocessing import DataPreprocessor

os.makedirs('data/models', exist_ok=True)
os.makedirs('data/processed/results', exist_ok=True)

print("="*80)
print("INTELLIGENT IDS - MODEL TRAINING PIPELINE")
print("="*80)
print(f"Training started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("="*80)

print("\n[STEP 1/6] Loading and preprocessing data...")
preprocessor = DataPreprocessor()
df = preprocessor.load_data('data/raw/CICIDS2017.csv')

print("\n[STEP 2/6] Cleaning data...")
df = preprocessor.clean_data(df)

print("\n[STEP 3/6] Preparing features...")
X, y = preprocessor.prepare_features(df)

print("\n[STEP 4/6] Balancing dataset...")

num_classes = len(np.unique(y))
if num_classes > 1:
    X_balanced, y_balanced = preprocessor.balance_data(X, y, method='smote')
else:
    print("\n" + "!"*80)
    print("WARNING: Dataset contains only ONE class (BENIGN)")
    print("!"*80)
    print("SMOTE balancing requires at least 2 classes.")
    print("Skipping balancing step. Using original data for training.")
    print("NOTE: This model will only learn benign patterns.")
    print("For a real IDS, you need a dataset with attack samples.")
    print("!"*80 + "\n")
    X_balanced, y_balanced = X, y

print("\n[STEP 5/6] Splitting data...")
X_train, X_val, X_test, y_train, y_val, y_test = preprocessor.split_data(
    X_balanced, y_balanced, test_size=0.2, val_size=0.1
)

print("\n[STEP 6/6] Training XGBoost model...")
print("="*80)

xgb_params = {
    'n_estimators': 200,
    'max_depth': 10,
    'learning_rate': 0.1,
    'subsample': 0.8,
    'colsample_bytree': 0.8,
    'objective': 'multi:softmax',
    'num_class': len(preprocessor.label_encoder.classes_),
    'random_state': 42,
    'n_jobs': -1,
    'eval_metric': 'mlogloss'
}

print("\nXGBoost parameters:")
for key, value in xgb_params.items():
    print(f"  {key}: {value}")

print("\nTraining XGBoost classifier...")
model = xgb.XGBClassifier(**xgb_params)

eval_set = [(X_train, y_train), (X_val, y_val)]
model.fit(
    X_train, y_train,
    eval_set=eval_set,
    verbose=True
)

print("\n" + "="*80)
print("MODEL EVALUATION")
print("="*80)

print("\n[1] Validation Set Performance:")
y_val_pred = model.predict(X_val)
val_accuracy = accuracy_score(y_val, y_val_pred)
val_precision = precision_score(y_val, y_val_pred, average='weighted', zero_division=0)
val_recall = recall_score(y_val, y_val_pred, average='weighted', zero_division=0)
val_f1 = f1_score(y_val, y_val_pred, average='weighted', zero_division=0)

print(f"Accuracy:  {val_accuracy:.4f} ({val_accuracy*100:.2f}%)")
print(f"Precision: {val_precision:.4f}")
print(f"Recall:    {val_recall:.4f}")
print(f"F1-Score:  {val_f1:.4f}")

print("\n[2] Test Set Performance:")
y_test_pred = model.predict(X_test)
test_accuracy = accuracy_score(y_test, y_test_pred)
test_precision = precision_score(y_test, y_test_pred, average='weighted', zero_division=0)
test_recall = recall_score(y_test, y_test_pred, average='weighted', zero_division=0)
test_f1 = f1_score(y_test, y_test_pred, average='weighted', zero_division=0)

print(f"Accuracy:  {test_accuracy:.4f} ({test_accuracy*100:.2f}%)")
print(f"Precision: {test_precision:.4f}")
print(f"Recall:    {test_recall:.4f}")
print(f"F1-Score:  {test_f1:.4f}")

print("\n[3] Detailed Classification Report (Test Set):")
target_names = preprocessor.label_encoder.classes_
print(classification_report(y_test, y_test_pred, target_names=target_names, zero_division=0))

print("\n[4] Confusion Matrix:")
cm = confusion_matrix(y_test, y_test_pred)
print(cm)

print("\n[5] Creating confusion matrix visualization...")
plt.figure(figsize=(12, 10))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
            xticklabels=target_names, 
            yticklabels=target_names,
            cbar_kws={'label': 'Count'})
plt.title('Confusion Matrix - XGBoost Model', fontsize=16, fontweight='bold', pad=20)
plt.ylabel('True Label', fontsize=12, fontweight='bold')
plt.xlabel('Predicted Label', fontsize=12, fontweight='bold')
plt.xticks(rotation=45, ha='right')
plt.yticks(rotation=0)
plt.tight_layout()
plt.savefig('data/processed/results/confusion_matrix.png', dpi=300, bbox_inches='tight')
plt.close()
print("Saved: data/processed/results/confusion_matrix.png")

print("\n[6] Feature importance analysis...")
feature_importance = model.feature_importances_
feature_importance_df = pd.DataFrame({
    'feature': preprocessor.feature_names,
    'importance': feature_importance
}).sort_values('importance', ascending=False)

print("\nTop 20 most important features:")
print(feature_importance_df.head(20).to_string(index=False))

plt.figure(figsize=(12, 10))
top_features = feature_importance_df.head(20)
plt.barh(range(len(top_features)), top_features['importance'].values, color='steelblue')
plt.yticks(range(len(top_features)), top_features['feature'].values)
plt.xlabel('Importance Score', fontsize=12, fontweight='bold')
plt.ylabel('Feature', fontsize=12, fontweight='bold')
plt.title('Top 20 Most Important Features', fontsize=16, fontweight='bold', pad=20)
plt.gca().invert_yaxis()
plt.grid(axis='x', alpha=0.3)
plt.tight_layout()
plt.savefig('data/processed/results/feature_importance.png', dpi=300, bbox_inches='tight')
plt.close()
print("Saved: data/processed/results/feature_importance.png")

print("\n[7] Per-class accuracy analysis...")
class_accuracies = []
for idx, label in enumerate(target_names):
    mask = y_test == idx
    if mask.sum() > 0:
        class_acc = accuracy_score(y_test[mask], y_test_pred[mask])
        class_accuracies.append({
            'class': label,
            'accuracy': class_acc,
            'samples': mask.sum()
        })
        print(f"{label:<30} : {class_acc:.4f} ({mask.sum():,} samples)")

print("\n" + "="*80)
print("SAVING MODEL AND RESULTS")
print("="*80)

print("\nSaving XGBoost model...")
joblib.dump(model, 'data/models/xgboost_model.pkl')
print("Saved: data/models/xgboost_model.pkl")

print("\nSaving preprocessor...")
preprocessor.save_preprocessor('data/models/preprocessor.pkl')

results = {
    'training_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    'model_type': 'XGBoost',
    'dataset_info': {
        'total_samples': int(len(df)),
        'training_samples': int(len(X_train)),
        'validation_samples': int(len(X_val)),
        'test_samples': int(len(X_test)),
        'num_features': len(preprocessor.feature_names),
        'num_classes': len(target_names),
        'classes': target_names.tolist()
    },
    'model_parameters': xgb_params,
    'validation_metrics': {
        'accuracy': float(val_accuracy),
        'precision': float(val_precision),
        'recall': float(val_recall),
        'f1_score': float(val_f1)
    },
    'test_metrics': {
        'accuracy': float(test_accuracy),
        'precision': float(test_precision),
        'recall': float(test_recall),
        'f1_score': float(test_f1)
    },
    'per_class_accuracy': class_accuracies,
    'top_10_features': feature_importance_df.head(10).to_dict('records')
}

import json
with open('data/processed/results/training_results.json', 'w') as f:
    json.dump(results, f, indent=4)
print("Saved: data/processed/results/training_results.json")

feature_importance_df.to_csv('data/processed/results/feature_importance.csv', index=False)
print("Saved: data/processed/results/feature_importance.csv")

print("\n" + "="*80)
print("TRAINING COMPLETE!")
print("="*80)
print(f"\nFinal Test Accuracy: {test_accuracy:.4f} ({test_accuracy*100:.2f}%)")
print(f"\nModel files saved in: data/models/")
print(f"Results saved in: data/processed/results/")
print("\nGenerated files:")
print("  1. data/models/xgboost_model.pkl")
print("  2. data/models/preprocessor.pkl")
print("  3. data/processed/results/training_results.json")
print("  4. data/processed/results/confusion_matrix.png")
print("  5. data/processed/results/feature_importance.png")
print("  6. data/processed/results/feature_importance.csv")
print("="*80)
print(f"\nTraining completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("="*80)