import joblib
import pickle

print("Checking preprocessor contents...")

try:
    preprocessor = joblib.load('../data/models/preprocessor_nslkdd.pkl')
    print(f"\nPreprocessor type: {type(preprocessor)}")
    print(f"\nPreprocessor contents:")
    
    if isinstance(preprocessor, dict):
        print("It's a dictionary with keys:")
        for key in preprocessor.keys():
            print(f"  - {key}: {type(preprocessor[key])}")
    else:
        print(preprocessor)
        
except Exception as e:
    print(f"Error: {e}")