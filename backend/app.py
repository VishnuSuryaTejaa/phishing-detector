"""
Flask API for Phishing Link Detection
Provides REST endpoint for URL classification
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import os
from feature_extractor import URLFeatureExtractor


from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import os
import numpy as np
from feature_extractor import URLFeatureExtractor

app = Flask(__name__)
CORS(app)  # Enable CORS for frontend communication

# Global variables
model = None
extractor = None
vectorizer = None
model_type = "unknown"  # 'legacy' (manual features) or 'tfidf' (vectorizer)

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, 'phishing_model.pkl')
EXTRACTOR_PATH = os.path.join(BASE_DIR, 'feature_extractor.pkl')
VECTORIZER_PATH = os.path.join(BASE_DIR, '..', 'vectorizer.pkl')  # Check root first

def load_model():
    """Load the trained model and appropriate feature extractor"""
    global model, extractor, vectorizer, model_type
    
    print(f"Loading model from: {MODEL_PATH}")
    
    if not os.path.exists(MODEL_PATH):
        print("⚠️  Model file not found. Please place 'phishing_model.pkl' in the backend directory.")
        return False
    
    try:
        model = joblib.load(MODEL_PATH)
        print("✓ Model loaded successfully!")
        
        # Determine model type based on feature count
        if hasattr(model, 'n_features_in_'):
            n_features = model.n_features_in_
            print(f"Model expects {n_features} features.")
            
            if n_features > 100:
                print("Detected TF-IDF model architecture.")
                model_type = 'tfidf'
                
                # Try loading vectorizer
                if os.path.exists(VECTORIZER_PATH):
                    vectorizer = joblib.load(VECTORIZER_PATH)
                    print(f"✓ Vectorizer loaded from {VECTORIZER_PATH}")
                    return True
                elif os.path.exists(os.path.join(BASE_DIR, 'vectorizer.pkl')):
                     vectorizer = joblib.load(os.path.join(BASE_DIR, 'vectorizer.pkl'))
                     print(f"✓ Vectorizer loaded from backend directory")
                     return True
                else:
                    print("❌ Error: TF-IDF model requires 'vectorizer.pkl'. File not found.")
                    return False
            else:
                print("Detected Legacy (Manual Feature) model architecture.")
                model_type = 'legacy'
                
                if os.path.exists(EXTRACTOR_PATH):
                    extractor = joblib.load(EXTRACTOR_PATH)
                    print("✓ Feature Extractor loaded.")
                    return True
                else:
                    print("⚠️ Feature Extractor not found, initializing new one.")
                    extractor = URLFeatureExtractor()
                    return True
        else:
            print("⚠️ Model does not have 'n_features_in_' attribute. Assuming Legacy.")
            model_type = 'legacy'
            if os.path.exists(EXTRACTOR_PATH):
                extractor = joblib.load(EXTRACTOR_PATH)
            else:
                extractor = URLFeatureExtractor()
            return True
            
    except Exception as e:
        print(f"✗ Error loading model: {e}")
        return False


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'model_loaded': model is not None,
        'model_type': model_type
    })


@app.route('/api/predict', methods=['POST'])
def predict():
    """Predict if a URL is phishing or legitimate"""
    
    # Check if model is loaded
    if model is None:
        return jsonify({
            'error': 'Model not loaded. Please checkout the logs.'
        }), 503
    
    # Get URL from request
    data = request.get_json()
    
    if not data or 'url' not in data:
        return jsonify({
            'error': 'Missing "url" field in request body'
        }), 400
    
    url = data['url'].strip()
    
    if not url:
        return jsonify({
            'error': 'URL cannot be empty'
        }), 400
    

    try:
        if model_type == 'tfidf':
            # TF-IDF Prediction Path
            if vectorizer is None:
                 return jsonify({'error': 'Vectorizer not loaded for TF-IDF model'}), 500
                 
            feature_vector = vectorizer.transform([url])
            prediction = model.predict(feature_vector)[0]
            probabilities = model.predict_proba(feature_vector)[0]
            
            # Invert logic for TF-IDF model: 0 is Phishing, 1 is Legitimate
            is_phishing = bool(prediction == 0)
            classification = 'phishing' if is_phishing else 'legitimate'
            confidence = {
                'legitimate': float(probabilities[1]),
                'phishing': float(probabilities[0])
            }
            confidence_score = float(max(probabilities))
            
            # Extract basic features for frontend display only (not used for prediction)
            # We initialize a temporary extractor just for display purposes
            temp_extractor = URLFeatureExtractor()
            features_dict = temp_extractor.extract_features(url)
            
        else:
            # Legacy Prediction Path
            if extractor is None:
                 return jsonify({'error': 'Extractor not loaded for legacy model'}), 500

            features_dict = extractor.extract_features(url)
            feature_vector = [[features_dict[name] for name in extractor.get_feature_names()]]
            
            prediction = model.predict(feature_vector)[0]
            probabilities = model.predict_proba(feature_vector)[0]
            
            # Standard logic: 1 is Phishing, 0 is Legitimate
            is_phishing = (prediction == 1)
            classification = 'phishing' if is_phishing else 'legitimate'
            confidence = {
                'legitimate': float(probabilities[0]),
                'phishing': float(probabilities[1])
            }
            confidence_score = float(max(probabilities))
        
        # Get network validation data
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url)
            # Use hostname if available (handles ports for netloc), otherwise fallback to path
            if parsed.netloc:
                domain = parsed.hostname
            else:
                domain = parsed.path.split('/')[0]
                # Remove port if present in path-only URL
                if ':' in domain:
                    domain = domain.split(':')[0]
            
            # Import network validator
            import sys
            
            # Add Network_Validator to path if not present
            nv_path = os.path.join(os.path.dirname(__file__), 'Network_Validator')
            if nv_path not in sys.path:
                sys.path.append(nv_path)
                
            from network.network_validator import network_scan
            
            if domain:
                network_data = network_scan(domain)
            else:
                network_data = None
        except Exception as e:
            print(f"Network validation failed: {e}")
            network_data = None
        
        # Prepare response
        result = {
            'url': url,
            'is_phishing': is_phishing,
            'classification': classification,
            'confidence': confidence,
            'confidence_score': confidence_score,
            'risk_level': get_risk_level(confidence['phishing']),
            'features': {
                'url_length': features_dict.get('url_length'),
                'has_https': features_dict.get('has_https') == 1,
                'has_ip_address': features_dict.get('has_ip_address') == 1,
                'has_suspicious_tld': features_dict.get('has_suspicious_tld') == 1,
                'num_suspicious_keywords': features_dict.get('num_suspicious_keywords'),
                'domain_entropy': round(features_dict.get('domain_entropy', 0), 2)
            },
            'model_type': model_type
        }
        
        # Add network validation data if available
        if network_data:
            result['network_analysis'] = {
                'dns_resolves': network_data.get('dns_resolves'),
                'ip_address': network_data.get('ip_address'),
                'domain_age_days': network_data.get('domain_age_days'),
                'ssl_valid': network_data.get('ssl_valid'),
                'hosting_country': network_data.get('hosting_country'),
                'isp': network_data.get('isp'),
                'network_risk_score': network_data.get('network_risk_score'),
                'risk_reasons': network_data.get('reasons', [])
            }
        
        return jsonify(result), 200
        
    except ValueError as e:
        return jsonify({
            'error': f'Invalid URL: {str(e)}'
        }), 400
    except Exception as e:
        return jsonify({
            'error': f'Prediction failed: {str(e)}'
        }), 500



def get_risk_level(phishing_probability):
    """Determine risk level based on phishing probability"""
    if phishing_probability >= 0.8:
        return 'high'
    elif phishing_probability >= 0.5:
        return 'medium'
    elif phishing_probability >= 0.3:
        return 'low'
    else:
        return 'safe'


@app.route('/api/batch-predict', methods=['POST'])
def batch_predict():
    """Predict multiple URLs at once"""
    
    if model is None:
        return jsonify({
            'error': 'Model not loaded.'
        }), 503
    
    data = request.get_json()
    
    if not data or 'urls' not in data:
        return jsonify({
            'error': 'Missing "urls" field in request body'
        }), 400
    
    urls = data['urls']
    
    if not isinstance(urls, list):
        return jsonify({
            'error': '"urls" must be an array'
        }), 400
    
    results = []
    
    for url in urls:
        try:
            if model_type == 'tfidf':
                if vectorizer is None:
                    raise Exception("Vectorizer not loaded")
                feature_vector = vectorizer.transform([url])
                prediction = model.predict(feature_vector)[0]
                probabilities = model.predict_proba(feature_vector)[0]
                
                # Invert logic: 0 is Phishing, 1 is Legitimate
                is_phishing = bool(prediction == 0)
                classification = 'phishing' if is_phishing else 'legitimate'
                confidence_score = float(max(probabilities))
                
            else:
                if extractor is None:
                    raise Exception("Extractor not loaded")
                features_dict = extractor.extract_features(url)
                feature_vector = [[features_dict[name] for name in extractor.get_feature_names()]]
                prediction = model.predict(feature_vector)[0]
                probabilities = model.predict_proba(feature_vector)[0]
                
                # Standard logic: 1 is Phishing, 0 is Legitimate
                is_phishing = (prediction == 1)
                classification = 'phishing' if is_phishing else 'legitimate'
                confidence_score = float(max(probabilities))
            
            results.append({
                'url': url,
                'is_phishing': is_phishing,
                'classification': classification,
                'confidence_score': confidence_score
            })
        except Exception as e:
            results.append({
                'url': url,
                'error': str(e)
            })
    
    return jsonify({'results': results}), 200


if __name__ == '__main__':
    print("="*50)
    print("PHISHING DETECTION API")
    print("="*50)
    
    # Load model
    if load_model():
        print("\n🚀 Starting Flask server...")
        print("📍 API Endpoints:")
        print("   GET  /api/health")
        print("   POST /api/predict")
        print("   POST /api/batch-predict")
        print(f"   Model Type: {model_type}")
        print("\n" + "="*50)
        app.run(debug=True, host='0.0.0.0', port=5001)
    else:
        print("\n❌ Failed to start. Please populate 'phishing_model.pkl' first.")
