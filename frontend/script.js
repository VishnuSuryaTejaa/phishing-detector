/**
 * Phishing Detection Frontend
 * Handles API communication and UI interactions
 */

// Configuration
const API_URL = 'http://localhost:5001/api';

// DOM Elements
const scanForm = document.getElementById('scanForm');
const urlInput = document.getElementById('urlInput');
const scanButton = document.getElementById('scanButton');
const loadingState = document.getElementById('loadingState');
const resultCard = document.getElementById('resultCard');
const scanAnotherButton = document.getElementById('scanAnotherButton');
const statusBadge = document.getElementById('statusBadge');

// Result elements
const resultIcon = document.getElementById('resultIcon');
const resultTitle = document.getElementById('resultTitle');
const resultClassification = document.getElementById('resultClassification');
const resultUrl = document.getElementById('resultUrl');
const confidenceValue = document.getElementById('confidenceValue');
const confidenceFill = document.getElementById('confidenceFill');
const riskBadge = document.getElementById('riskBadge');
const riskValue = document.getElementById('riskValue');

// Initialize
checkAPIHealth();

// Event Listeners
scanForm.addEventListener('submit', handleScan);
scanAnotherButton.addEventListener('click', resetForm);

/**
 * Check if API is available
 */
async function checkAPIHealth() {
    try {
        const response = await fetch(`${API_URL}/health`);
        const data = await response.json();

        if (data.status === 'healthy' && data.model_loaded) {
            updateStatusBadge(true, 'API Ready');
        } else {
            updateStatusBadge(false, 'Model Not Loaded');
        }
    } catch (error) {
        updateStatusBadge(false, 'API Offline');
        console.error('API health check failed:', error);
    }
}

/**
 * Update status badge
 */
function updateStatusBadge(isHealthy, text) {
    const statusDot = statusBadge.querySelector('.status-dot');
    const statusText = statusBadge.querySelector('span:last-child');

    if (isHealthy) {
        statusDot.style.background = 'var(--color-success)';
    } else {
        statusDot.style.background = 'var(--color-danger)';
    }

    statusText.textContent = text;
}

/**
 * Handle form submission
 */
async function handleScan(e) {
    e.preventDefault();

    const url = urlInput.value.trim();

    if (!url) {
        showError('Please enter a URL');
        return;
    }

    // Show loading state
    scanForm.classList.add('hidden');
    resultCard.classList.add('hidden');
    loadingState.classList.remove('hidden');

    try {
        const response = await fetch(`${API_URL}/predict`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url }),
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || 'Prediction failed');
        }

        const data = await response.json();
        displayResult(data);

    } catch (error) {
        console.error('Scan error:', error);
        showError(error.message || 'Failed to scan URL. Please ensure the backend is running.');
        scanForm.classList.remove('hidden');
        loadingState.classList.add('hidden');
    }
}

/**
 * Display scan result
 */
function displayResult(data) {
    loadingState.classList.add('hidden');
    resultCard.classList.remove('hidden');

    const isPhishing = data.is_phishing;
    const confidence = data.confidence_score * 100;
    const riskLevel = data.risk_level;

    // Update icon
    resultIcon.innerHTML = isPhishing
        ? '⚠️'
        : '✅';

    resultIcon.className = 'result-icon ' + (isPhishing ? 'phishing' : 'safe');

    // Update title
    resultTitle.textContent = isPhishing
        ? 'Phishing Detected!'
        : 'URL is Safe';

    // Update classification
    resultClassification.textContent = data.classification.charAt(0).toUpperCase() + data.classification.slice(1);
    resultClassification.className = 'result-classification ' + (isPhishing ? 'phishing' : 'safe');

    // Update URL
    resultUrl.textContent = data.url;

    // Update confidence
    confidenceValue.textContent = `${confidence.toFixed(1)}%`;
    confidenceFill.style.width = `${confidence}%`;

    // Update risk level
    riskValue.textContent = riskLevel.charAt(0).toUpperCase() + riskLevel.slice(1);
    riskBadge.className = 'risk-badge ' + riskLevel;

    // Add animation
    resultCard.style.animation = 'none';
    setTimeout(() => {
        resultCard.style.animation = 'slideUp 0.4s ease-out';
    }, 10);
}

/**
 * Reset form to initial state
 */
function resetForm() {
    urlInput.value = '';
    resultCard.classList.add('hidden');
    scanForm.classList.remove('hidden');
    urlInput.focus();
}

/**
 * Show error message
 */
function showError(message) {
    // Create temporary error div
    const errorDiv = document.createElement('div');
    errorDiv.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: var(--color-danger-bg);
        border: 2px solid var(--color-danger);
        color: var(--color-danger);
        padding: 1rem 1.5rem;
        border-radius: var(--radius-md);
        font-weight: 600;
        z-index: 1000;
        animation: slideUp 0.3s ease-out;
    `;
    errorDiv.textContent = message;

    document.body.appendChild(errorDiv);

    setTimeout(() => {
        errorDiv.style.animation = 'slideDown 0.3s ease-out';
        setTimeout(() => errorDiv.remove(), 300);
    }, 3000);
}

// Add slideDown animation
const style = document.createElement('style');
style.textContent = `
    @keyframes slideDown {
        to {
            opacity: 0;
            transform: translateY(-20px);
        }
    }
`;
document.head.appendChild(style);
