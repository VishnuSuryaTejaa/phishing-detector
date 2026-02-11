"""
Flask API for Phishing Link Detection
Provides REST endpoint for URL classification
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import os
from feature_extractor import URLFeatureExtractor

app = Flask(__name__)
CORS(app)  # Enable CORS for frontend communication

# Load model and feature extractor
MODEL_PATH = 'phishing_model.pkl'
EXTRACTOR_PATH = 'feature_extractor.pkl'

model = None
extractor = None

def load_model():
    """Load the trained model and feature extractor"""
    global model, extractor
    
    if not os.path.exists(MODEL_PATH) or not os.path.exists(EXTRACTOR_PATH):
        print("⚠️  Model files not found. Please run train_model.py first.")
        return False
    
    try:
        model = joblib.load(MODEL_PATH)
        extractor = joblib.load(EXTRACTOR_PATH)
        print("✓ Model loaded successfully!")
        return True
    except Exception as e:
        print(f"✗ Error loading model: {e}")
        return False


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'model_loaded': model is not None
    })


@app.route('/api/predict', methods=['POST'])
def predict():
    """Predict if a URL is phishing or legitimate"""
    
    # Check if model is loaded
    if model is None or extractor is None:
        return jsonify({
            'error': 'Model not loaded. Please train the model first.'
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
        # Extract features
        features_dict = extractor.extract_features(url)
        feature_vector = [[features_dict[name] for name in extractor.get_feature_names()]]
        
        # Make prediction
        prediction = model.predict(feature_vector)[0]
        probabilities = model.predict_proba(feature_vector)[0]
        
        # Prepare response
        result = {
            'url': url,
            'is_phishing': bool(prediction),
            'classification': 'phishing' if prediction == 1 else 'legitimate',
            'confidence': {
                'legitimate': float(probabilities[0]),
                'phishing': float(probabilities[1])
            },
            'confidence_score': float(max(probabilities)),
            'risk_level': get_risk_level(probabilities[1])
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
    
    if model is None or extractor is None:
        return jsonify({
            'error': 'Model not loaded. Please train the model first.'
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
            features_dict = extractor.extract_features(url)
            feature_vector = [[features_dict[name] for name in extractor.get_feature_names()]]
            
            prediction = model.predict(feature_vector)[0]
            probabilities = model.predict_proba(feature_vector)[0]
            
            results.append({
                'url': url,
                'is_phishing': bool(prediction),
                'classification': 'phishing' if prediction == 1 else 'legitimate',
                'confidence_score': float(max(probabilities))
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
        print("\n" + "="*50)
        app.run(debug=True, host='0.0.0.0', port=5001)
    else:
        print("\n❌ Failed to start. Please run 'python train_model.py' first.")
