"""
ML Model Integration for Real-time IDS Predictions
Loads trained XGBoost model and makes predictions on network traffic
"""

import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from datetime import datetime

class IDSPredictor:
    def __init__(self, model_path='data/models/xgboost_nslkdd_model.pkl', 
                 preprocessor_path='data/models/preprocessor_nslkdd.pkl'):
        """
        Initialize the IDS predictor with trained models
        
        Args:
            model_path: Path to trained XGBoost model
            preprocessor_path: Path to preprocessor (scaler, label_encoder, feature_names)
        """
        self.model_path = Path(model_path)
        self.preprocessor_path = Path(preprocessor_path)
        
        self.model = None
        self.scaler = None
        self.label_encoder = None
        self.feature_names = None
        self.is_loaded = False
        
        self.load_models()
    
    def load_models(self):
        """Load the trained model and preprocessor"""
        try:
            print(f"Loading model from: {self.model_path}")
            self.model = joblib.load(self.model_path)
            print("✓ XGBoost model loaded successfully")
            
            print(f"Loading preprocessor from: {self.preprocessor_path}")
            preprocessor_data = joblib.load(self.preprocessor_path)
            
            self.scaler = preprocessor_data['scaler']
            self.label_encoder = preprocessor_data['label_encoder']
            self.feature_names = preprocessor_data['feature_names']
            
            print(f"✓ Preprocessor loaded successfully")
            print(f"  - Features: {len(self.feature_names)}")
            print(f"  - Attack classes: {len(self.label_encoder.classes_)}")
            print(f"  - Classes: {', '.join(self.label_encoder.classes_[:10])}...")
            
            self.is_loaded = True
            return True
            
        except FileNotFoundError as e:
            print(f"✗ Error: Model files not found!")
            print(f"  Make sure these files exist:")
            print(f"  1. {self.model_path}")
            print(f"  2. {self.preprocessor_path}")
            print(f"\n  Run 'python train_nslkdd_final.py' to train the model first")
            self.is_loaded = False
            return False
            
        except Exception as e:
            print(f"✗ Error loading models: {e}")
            self.is_loaded = False
            return False
    
    def preprocess_features(self, features_dict):
        """
        Preprocess raw network traffic features for prediction
        
        Args:
            features_dict: Dictionary of network features
            
        Returns:
            Preprocessed feature array ready for prediction
        """
        if not self.is_loaded:
            raise RuntimeError("Models not loaded. Cannot make predictions.")
        
        # Convert dict to DataFrame with correct feature names
        df = pd.DataFrame([features_dict])
        
        # Ensure all required features are present
        missing_features = set(self.feature_names) - set(df.columns)
        if missing_features:
            # Add missing features with default value 0
            for feature in missing_features:
                df[feature] = 0
        
        # Reorder columns to match training
        df = df[self.feature_names]
        
        # Scale features
        features_scaled = self.scaler.transform(df)
        
        return features_scaled
    
    def predict(self, features_dict):
        """
        Make prediction on network traffic
        
        Args:
            features_dict: Dictionary of network features
            
        Returns:
            Dictionary with prediction, confidence, and details
        """
        if not self.is_loaded:
            return {
                'error': 'Model not loaded',
                'prediction': 'unknown',
                'confidence': 0.0,
                'is_attack': False
            }
        
        try:
            # Preprocess features
            features_scaled = self.preprocess_features(features_dict)
            
            # Make prediction
            prediction_encoded = self.model.predict(features_scaled)[0]
            prediction_proba = self.model.predict_proba(features_scaled)[0]
            
            # Decode prediction
            prediction = self.label_encoder.inverse_transform([prediction_encoded])[0]
            confidence = float(prediction_proba[prediction_encoded])
            
            # Determine if it's an attack
            is_attack = prediction.lower() != 'normal'
            
            # Get top 3 predictions
            top_3_idx = np.argsort(prediction_proba)[-3:][::-1]
            top_3_predictions = [
                {
                    'class': self.label_encoder.inverse_transform([idx])[0],
                    'probability': float(prediction_proba[idx])
                }
                for idx in top_3_idx
            ]
            
            return {
                'prediction': prediction,
                'confidence': confidence,
                'is_attack': is_attack,
                'timestamp': datetime.now().isoformat(),
                'top_3_predictions': top_3_predictions
            }
            
        except Exception as e:
            print(f"Error during prediction: {e}")
            return {
                'error': str(e),
                'prediction': 'error',
                'confidence': 0.0,
                'is_attack': False
            }
    
    def predict_batch(self, features_list):
        """
        Make predictions on multiple network traffic samples
        
        Args:
            features_list: List of feature dictionaries
            
        Returns:
            List of prediction dictionaries
        """
        if not self.is_loaded:
            return [{'error': 'Model not loaded'}] * len(features_list)
        
        results = []
        for features in features_list:
            result = self.predict(features)
            results.append(result)
        
        return results
    
    def get_model_info(self):
        """Get information about loaded model"""
        if not self.is_loaded:
            return {
                'loaded': False,
                'error': 'Model not loaded'
            }
        
        return {
            'loaded': True,
            'model_type': 'XGBoost Classifier',
            'dataset': 'NSL-KDD',
            'num_features': len(self.feature_names),
            'num_classes': len(self.label_encoder.classes_),
            'classes': list(self.label_encoder.classes_),
            'feature_names': self.feature_names[:20]  # First 20 features
        }


# Example usage
if __name__ == "__main__":
    # Initialize predictor
    predictor = IDSPredictor()
    
    if predictor.is_loaded:
        # Get model info
        info = predictor.get_model_info()
        print("\n" + "="*80)
        print("MODEL INFORMATION")
        print("="*80)
        print(f"Model Type: {info['model_type']}")
        print(f"Dataset: {info['dataset']}")
        print(f"Features: {info['num_features']}")
        print(f"Classes: {info['num_classes']}")
        print("\nFirst 20 feature names:")
        for i, feature in enumerate(info['feature_names'], 1):
            print(f"  {i:2d}. {feature}")
        
        # Example prediction (you'll need to provide actual feature values)
        print("\n" + "="*80)
        print("EXAMPLE PREDICTION")
        print("="*80)
        
        # Create example features (zeros for now - replace with actual traffic data)
        example_features = {feature: 0 for feature in predictor.feature_names}
        
        # Make prediction
        result = predictor.predict(example_features)
        
        print(f"Prediction: {result['prediction']}")
        print(f"Confidence: {result['confidence']:.4f}")
        print(f"Is Attack: {result['is_attack']}")
        print("\nTop 3 predictions:")
        for i, pred in enumerate(result['top_3_predictions'], 1):
            print(f"  {i}. {pred['class']:<20} - {pred['probability']:.4f}")
    
    else:
        print("\n✗ Failed to load models!")
        print("Please train the model first: python train_nslkdd_final.py")