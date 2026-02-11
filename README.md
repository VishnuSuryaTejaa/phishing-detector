# 🛡️ Phishing Link Detector

An AI-powered phishing detection system using machine learning to identify malicious URLs. Built with Flask, scikit-learn, and a modern cybersecurity-themed frontend.

![Phishing Detection](https://img.shields.io/badge/Security-Phishing%20Detection-blue)
![Python](https://img.shields.io/badge/Python-3.8+-green)
![Flask](https://img.shields.io/badge/Flask-3.0-black)
![ML](https://img.shields.io/badge/ML-Random%20Forest-orange)

## ✨ Features

- 🧠 **Machine Learning**: Random Forest classifier with 22+ URL features
- ⚡ **Real-time Analysis**: Instant URL scanning and classification
- 🎨 **Modern UI**: Cybersecurity-themed design with glassmorphism effects
- 🔒 **Privacy-focused**: No data storage, all analysis server-side
- 📊 **Detailed Results**: Confidence scores and risk level indicators

## 🏗️ Architecture

```
phishing-detector/
├── backend/
│   ├── app.py                  # Flask API server
│   ├── feature_extractor.py    # URL feature extraction
│   ├── train_model.py          # Model training script
│   ├── requirements.txt        # Python dependencies
│   ├── phishing_model.pkl      # Trained model (generated)
│   └── feature_extractor.pkl   # Feature extractor (generated)
└── frontend/
    ├── index.html              # Main HTML page
    ├── styles.css              # Styling with CSS variables
    └── script.js               # API integration & UI logic
```

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Modern web browser

### Installation

1. **Clone or navigate to the project directory**

```bash
cd /Users/apple/.gemini/antigravity/scratch/phishing-detector
```

2. **Install backend dependencies**

```bash
cd backend
pip install -r requirements.txt
```

3. **Train the ML model**

```bash
python train_model.py
```

This will:
- Generate synthetic training data (legitimate + phishing URLs)
- Extract features from each URL
- Train a Random Forest classifier
- Save the model to `phishing_model.pkl`

Expected output:
```
Total samples: 160
Legitimate: 80, Phishing: 80
Training Accuracy: ~95%
Testing Accuracy: ~90%
```

4. **Start the Flask API**

```bash
python app.py
```

The API will run on `http://localhost:5000`

5. **Open the frontend**

In a new terminal:
```bash
cd ../frontend
open index.html
```

Or simply open `frontend/index.html` in your browser.

## 📖 Usage

### Web Interface

1. Open `frontend/index.html` in your browser
2. Enter a URL in the input field
3. Click "Scan URL"
4. View the analysis results with:
   - Classification (Legitimate/Phishing)
   - Confidence score
   - Risk level

### API Endpoints

#### Health Check
```bash
GET /api/health
```

Response:
```json
{
  "status": "healthy",
  "model_loaded": true
}
```

#### Predict Single URL
```bash
POST /api/predict
Content-Type: application/json

{
  "url": "https://example.com"
}
```

Response:
```json
{
  "url": "https://example.com",
  "is_phishing": false,
  "classification": "legitimate",
  "confidence": {
    "legitimate": 0.95,
    "phishing": 0.05
  },
  "confidence_score": 0.95,
  "risk_level": "safe"
}
```

#### Batch Prediction
```bash
POST /api/batch-predict
Content-Type: application/json

{
  "urls": [
    "https://google.com",
    "http://192.168.1.1/login.php"
  ]
}
```

## 🔍 How It Works

### Feature Extraction (22+ Features)

The model analyzes URLs based on:

**Basic Features:**
- URL length
- Domain length
- Protocol (HTTP/HTTPS)

**Character Patterns:**
- Number of dots, hyphens, slashes
- Special character ratios
- Digit density

**Suspicious Indicators:**
- IP address usage
- Suspicious TLDs (.tk, .ml, .ga)
- Phishing keywords (login, verify, secure, etc.)
- Subdomain depth

**Statistical Features:**
- Domain entropy (randomness)
- Path and query length

### Model Training

- **Algorithm**: Random Forest (100 trees, max depth 10)
- **Training Data**: Synthetic dataset with 160 samples
  - 80 legitimate URLs (Google, GitHub, Amazon, etc.)
  - 80 phishing URLs (IP addresses, suspicious domains)
- **Performance**: ~90% test accuracy

## 🎨 Design Features

- **Glassmorphism**: Modern glass-like UI elements
- **Gradient Effects**: Cybersecurity-themed color palette
- **Smooth Animations**: Micro-interactions and transitions
- **Responsive Design**: Mobile-first approach
- **Dark Theme**: Easy on the eyes with vibrant accents

## 🧪 Example URLs to Test

**Legitimate:**
- `https://github.com/login`
- `https://www.google.com`
- `https://www.paypal.com`

**Phishing:**
- `http://192.168.1.1/secure-login.php`
- `https://paypal-secure-verify-account.tk/login`
- `http://google-com-login.ml/signin`

## 🔧 Configuration

### Backend Port
Edit `backend/app.py`:
```python
app.run(debug=True, host='0.0.0.0', port=5000)
```

### Frontend API URL
Edit `frontend/script.js`:
```javascript
const API_URL = 'http://localhost:5000/api';
```

## 📦 Dependencies

### Backend
- Flask 3.0.0 - Web framework
- Flask-CORS 4.0.0 - Cross-origin requests
- scikit-learn 1.3.2 - Machine learning
- pandas 2.1.4 - Data handling
- tldextract 5.1.1 - URL parsing
- validators 0.22.0 - URL validation

### Frontend
- Vanilla JavaScript (no dependencies)
- Google Fonts (Inter)

## 🚀 Deployment

### Backend (Render/Heroku)
1. Add `Procfile`:
   ```
   web: gunicorn app:app
   ```
2. Add `gunicorn` to `requirements.txt`
3. Deploy to your platform

### Frontend (Netlify/Vercel)
1. Update API URL in `script.js`
2. Deploy the `frontend` folder

## ⚠️ Limitations

- **Educational Purpose**: This is a demonstration system
- **Synthetic Data**: For production, use real labeled datasets
- **Feature-based**: Doesn't analyze page content
- **No URL Reputation**: Doesn't check external databases

## 🔮 Future Enhancements

- [ ] Real phishing dataset integration (PhishTank, OpenPhish)
- [ ] Deep learning model (LSTM/CNN)
- [ ] URL reputation checking
- [ ] Historical analysis and trends
- [ ] Browser extension
- [ ] Real-time phishing database updates

## 📄 License

MIT License - Feel free to use for educational purposes

## 🤝 Contributing

Suggestions and improvements welcome!

---

**Built with ❤️ for cybersecurity awareness**
