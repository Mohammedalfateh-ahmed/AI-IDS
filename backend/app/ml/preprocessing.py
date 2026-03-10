import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from imblearn.over_sampling import SMOTE
import joblib
import os

class DataPreprocessor:
    def __init__(self):
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.feature_names = None
        self.label_column = None
        
    def load_data(self, filepath):
        print(f"Loading data from {filepath}...")
        df = pd.read_csv(filepath)
        df.columns = df.columns.str.strip()
        print(f"Data loaded: {df.shape[0]:,} rows, {df.shape[1]} columns")
        return df
    
    def detect_label_column(self, df):
        possible_names = ['Label', 'label', 'class', 'Class', 'Attack', 'attack']
        for col in possible_names:
            if col in df.columns:
                self.label_column = col
                print(f"Label column detected: '{self.label_column}'")
                return self.label_column
        
        for col in df.columns:
            if 'label' in col.lower() or 'class' in col.lower():
                self.label_column = col
                print(f"Label column detected: '{self.label_column}'")
                return self.label_column
        
        raise ValueError("Could not find label column in dataset")
    
    def clean_data(self, df):
        print("\nCleaning data...")
        print(f"Original shape: {df.shape}")
        
        df = df.replace([np.inf, -np.inf], np.nan)
        
        before_drop = len(df)
        df = df.dropna()
        after_drop = len(df)
        print(f"Dropped {before_drop - after_drop:,} rows with NaN values")
        
        before_dup = len(df)
        df = df.drop_duplicates()
        after_dup = len(df)
        print(f"Dropped {before_dup - after_dup:,} duplicate rows")
        
        if 'Timestamp' in df.columns:
            df = df.drop('Timestamp', axis=1)
            print("Dropped Timestamp column")
        
        print(f"Final shape after cleaning: {df.shape}")
        return df
    
    def prepare_features(self, df):
        print("\nPreparing features...")
        
        if self.label_column is None:
            self.detect_label_column(df)
        
        X = df.drop(self.label_column, axis=1)
        y = df[self.label_column]
        
        print(f"Initial class distribution:")
        for label, count in y.value_counts().items():
            print(f"  {label}: {count:,} ({count/len(y)*100:.2f}%)")
        
        non_numeric_cols = X.select_dtypes(exclude=[np.number]).columns
        if len(non_numeric_cols) > 0:
            print(f"\nDropping non-numeric columns: {list(non_numeric_cols)}")
            X = X.drop(non_numeric_cols, axis=1)
        
        self.feature_names = X.columns.tolist()
        print(f"\nNumber of features: {len(self.feature_names)}")
        
        print("\nScaling features...")
        X_scaled = self.scaler.fit_transform(X)
        
        print("Encoding labels...")
        y_encoded = self.label_encoder.fit_transform(y)
        
        print(f"\nEncoded classes:")
        for idx, label in enumerate(self.label_encoder.classes_):
            count = np.sum(y_encoded == idx)
            print(f"  {idx}: {label} ({count:,} samples)")
        
        return X_scaled, y_encoded
    
    def balance_data(self, X, y, method='smote'):
        print(f"\nBalancing data using {method.upper()}...")
        print(f"Before balancing: {X.shape}")
        
        class_counts = np.bincount(y)
        print("Class distribution before:")
        for idx, count in enumerate(class_counts):
            label = self.label_encoder.classes_[idx]
            print(f"  {label}: {count:,}")
        
        if method == 'smote':
            smote = SMOTE(random_state=42, k_neighbors=5)
            X_balanced, y_balanced = smote.fit_resample(X, y)
        else:
            X_balanced, y_balanced = X, y
        
        print(f"\nAfter balancing: {X_balanced.shape}")
        class_counts_after = np.bincount(y_balanced)
        print("Class distribution after:")
        for idx, count in enumerate(class_counts_after):
            label = self.label_encoder.classes_[idx]
            print(f"  {label}: {count:,}")
        
        return X_balanced, y_balanced
    
    def split_data(self, X, y, test_size=0.2, val_size=0.1, random_state=42):
        print("\nSplitting data...")
        
        X_temp, X_test, y_temp, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state, stratify=y
        )
        
        val_size_adjusted = val_size / (1 - test_size)
        X_train, X_val, y_train, y_val = train_test_split(
            X_temp, y_temp, test_size=val_size_adjusted, 
            random_state=random_state, stratify=y_temp
        )
        
        print(f"Training set:   {X_train.shape[0]:,} samples ({X_train.shape[0]/len(X)*100:.1f}%)")
        print(f"Validation set: {X_val.shape[0]:,} samples ({X_val.shape[0]/len(X)*100:.1f}%)")
        print(f"Test set:       {X_test.shape[0]:,} samples ({X_test.shape[0]/len(X)*100:.1f}%)")
        
        return X_train, X_val, X_test, y_train, y_val, y_test
    
    def save_preprocessor(self, filepath='data/models/preprocessor.pkl'):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        joblib.dump({
            'scaler': self.scaler,
            'label_encoder': self.label_encoder,
            'feature_names': self.feature_names,
            'label_column': self.label_column
        }, filepath)
        print(f"\nPreprocessor saved to {filepath}")
    
    def load_preprocessor(self, filepath='data/models/preprocessor.pkl'):
        data = joblib.load(filepath)
        self.scaler = data['scaler']
        self.label_encoder = data['label_encoder']
        self.feature_names = data['feature_names']
        self.label_column = data.get('label_column', 'Label')
        print(f"Preprocessor loaded from {filepath}")
        return self