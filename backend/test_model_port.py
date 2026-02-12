
import joblib
import pandas as pd
from feature_extractor import URLFeatureExtractor

# Load model and extractor
try:
    model = joblib.load('backend/phishing_model.pkl')
    extractor = joblib.load('backend/feature_extractor.pkl')
except:
    # Try local path
    model = joblib.load('phishing_model.pkl')
    extractor = joblib.load('feature_extractor.pkl')

urls = [
    "https://google.com",
    "https://google.com:443",
    "https://www.google.com/search?q=test"
]

print(f"{'URL':<40} | {'Pred':<10} | {'Conf':<10} | {'Legit %':<10}")
print("-" * 80)

for url in urls:
    features = extractor.extract_features(url)
    vector = [[features[name] for name in extractor.get_feature_names()]]
    prob = model.predict_proba(vector)[0]
    pred = model.predict(vector)[0]
    class_label = "Phishing" if pred == 1 else "Legitimate"
    
    print(f"{url:<40} | {class_label:<10} | {max(prob):.4f}     | {prob[0]:.4f}")
