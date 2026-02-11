"""
Train the phishing detection model
Generates synthetic training data and trains a Random Forest classifier
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import joblib
from feature_extractor import URLFeatureExtractor


def generate_training_data():
    """Generate synthetic training data based on phishing patterns"""
    
    # Legitimate URLs (label = 0)
    legitimate_urls = [
        'https://www.google.com',
        'https://github.com/login',
        'https://www.amazon.com/products',
        'https://stackoverflow.com/questions',
        'https://www.youtube.com/watch',
        'https://www.wikipedia.org/wiki/Main_Page',
        'https://www.reddit.com/r/technology',
        'https://www.facebook.com',
        'https://twitter.com/home',
        'https://www.linkedin.com/feed',
        'https://www.microsoft.com/en-us',
        'https://www.apple.com/iphone',
        'https://www.netflix.com/browse',
        'https://www.cnn.com/world',
        'https://www.bbc.com/news',
        'https://docs.python.org/3/',
        'https://www.npmjs.com/package/express',
        'https://www.medium.com/articles',
        'https://www.paypal.com',
        'https://mail.google.com/mail',
    ]
    
    # Generate variations of legitimate URLs
    legitimate_variations = []
    for url in legitimate_urls:
        legitimate_variations.append(url)
        legitimate_variations.append(url + '/about')
        legitimate_variations.append(url + '?id=123')
        legitimate_variations.append(url + '/help/contact')
    
    # Phishing URLs (label = 1)
    phishing_urls = [
        'http://192.168.1.1/secure-login.php',
        'https://paypal-secure-verify-account.tk/login',
        'http://google-com-login.ml/signin',
        'https://account-update-microsoft.tk/verify',
        'http://255.255.255.0/update.html',
        'https://secure-banking-login-verify.cf/account',
        'http://amazon-account-suspended.gq/restore',
        'https://apple-id-verify-account.tk/signin',
        'http://netflix-account-hold.ml/update',
        'https://paypal.com-secure.tk/login',
        'http://verify-your-account-now.ml/confirm',
        'https://unusual-activity-detected.cf/verify',
        'http://click-here-to-confirm.gq/click',
        'https://your-account-has-been-suspended.tk/restore',
        'http://update-billing-information.ml/update',
        'https://secure-your-account-immediately.cf/secure',
        'http://confirm-identity-verification.gq/confirm',
        'https://restricted-account-access.tk/unlock',
        'http://banking-security-alert.ml/respond',
        'https://prize-winner-claim-now.cf/claim',
    ]
    
    # Generate variations of phishing URLs
    phishing_variations = []
    for url in phishing_urls:
        phishing_variations.append(url)
        phishing_variations.append(url + '?user=admin&pass=123')
        phishing_variations.append(url.replace('http://', 'https://'))
        phishing_variations.append(url + '&redirect=malicious.com')
    
    # Combine and label
    all_urls = legitimate_variations + phishing_variations
    labels = [0] * len(legitimate_variations) + [1] * len(phishing_variations)
    
    return all_urls, labels


def train_model():
    """Train the phishing detection model"""
    
    print("Generating training data...")
    urls, labels = generate_training_data()
    
    print(f"Total samples: {len(urls)}")
    print(f"Legitimate: {labels.count(0)}, Phishing: {labels.count(1)}")
    
    # Extract features
    print("\nExtracting features...")
    extractor = URLFeatureExtractor()
    feature_list = []
    valid_labels = []
    
    for url, label in zip(urls, labels):
        try:
            features = extractor.extract_features(url)
            feature_vector = [features[name] for name in extractor.get_feature_names()]
            feature_list.append(feature_vector)
            valid_labels.append(label)
        except Exception as e:
            print(f"Error processing {url}: {e}")
            continue
    
    # Create DataFrame
    X = pd.DataFrame(feature_list, columns=extractor.get_feature_names())
    y = np.array(valid_labels)
    
    print(f"\nFeature matrix shape: {X.shape}")
    print(f"Features: {list(X.columns)}")
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"\nTraining samples: {len(X_train)}")
    print(f"Testing samples: {len(X_test)}")
    
    # Train model
    print("\nTraining Random Forest classifier...")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42,
        n_jobs=-1
    )
    
    model.fit(X_train, y_train)
    
    # Evaluate
    print("\n" + "="*50)
    print("MODEL EVALUATION")
    print("="*50)
    
    train_predictions = model.predict(X_train)
    test_predictions = model.predict(X_test)
    
    train_accuracy = accuracy_score(y_train, train_predictions)
    test_accuracy = accuracy_score(y_test, test_predictions)
    
    print(f"\nTraining Accuracy: {train_accuracy:.4f}")
    print(f"Testing Accuracy: {test_accuracy:.4f}")
    
    print("\nClassification Report (Test Set):")
    print(classification_report(y_test, test_predictions, 
                                target_names=['Legitimate', 'Phishing']))
    
    print("\nConfusion Matrix (Test Set):")
    cm = confusion_matrix(y_test, test_predictions)
    print(f"True Negatives: {cm[0][0]}, False Positives: {cm[0][1]}")
    print(f"False Negatives: {cm[1][0]}, True Positives: {cm[1][1]}")
    
    # Feature importance
    print("\nTop 10 Most Important Features:")
    feature_importance = pd.DataFrame({
        'feature': extractor.get_feature_names(),
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    print(feature_importance.head(10).to_string(index=False))
    
    # Save model
    print("\nSaving model...")
    joblib.dump(model, 'phishing_model.pkl')
    joblib.dump(extractor, 'feature_extractor.pkl')
    
    print("\n✓ Model saved successfully!")
    print("  - phishing_model.pkl")
    print("  - feature_extractor.pkl")
    
    return model, extractor


if __name__ == '__main__':
    train_model()
