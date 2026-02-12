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

    // Update detailed confidence
    const legitConf = (data.confidence.legitimate * 100).toFixed(1);
    const phishConf = (data.confidence.phishing * 100).toFixed(1);
    document.getElementById('legitConfidence').textContent = `${legitConf}%`;
    document.getElementById('phishingConfidence').textContent = `${phishConf}%`;

    // Update risk level
    riskValue.textContent = riskLevel.charAt(0).toUpperCase() + riskLevel.slice(1);
    riskBadge.className = 'risk-badge ' + riskLevel;

    // Display URL features
    if (data.features) {
        const featureGrid = document.getElementById('featureGrid');
        featureGrid.innerHTML = '';
        
        const features = [
            { label: 'URL Length', value: data.features.url_length + ' chars', icon: '📏' },
            { label: 'HTTPS', value: data.features.has_https ? 'Yes' : 'No', icon: '🔒', highlight: !data.features.has_https },
            { label: 'IP Address', value: data.features.has_ip_address ? 'Yes' : 'No', icon: '🌐', highlight: data.features.has_ip_address },
            { label: 'Suspicious TLD', value: data.features.has_suspicious_tld ? 'Yes' : 'No', icon: '🏷️', highlight: data.features.has_suspicious_tld },
            { label: 'Phishing Keywords', value: data.features.num_suspicious_keywords, icon: '🔍', highlight: data.features.num_suspicious_keywords > 0 },
            { label: 'Domain Randomness', value: data.features.domain_entropy.toFixed(2), icon: '🎲' }
        ];

        features.forEach(feature => {
            const div = document.createElement('div');
            div.className = 'feature-item' + (feature.highlight ? ' warning' : '');
            div.innerHTML = `
                <span class="feature-icon">${feature.icon}</span>
                <div class="feature-content">
                    <span class="feature-label">${feature.label}</span>
                    <span class="feature-value">${feature.value}</span>
                </div>
            `;
            featureGrid.appendChild(div);
        });
    }

    // Display network analysis
    if (data.network_analysis) {
        const networkSection = document.getElementById('networkSection');
        const networkGrid = document.getElementById('networkGrid');
        networkSection.classList.remove('hidden');
        networkGrid.innerHTML = '';

        const network = data.network_analysis;
        const networkItems = [
            { label: 'DNS Status', value: network.dns_resolves ? 'Resolves' : 'Failed', icon: '🌍', highlight: !network.dns_resolves },
            { label: 'IP Address', value: network.ip_address || 'Unknown', icon: '📍' },
            { label: 'Domain Age', value: network.domain_age_days ? `${network.domain_age_days} days` : 'Unknown', icon: '📅', highlight: network.domain_age_days && network.domain_age_days < 90 },
            { label: 'SSL Certificate', value: network.ssl_valid ? 'Valid' : 'Invalid', icon: '🔐', highlight: !network.ssl_valid },
            { label: 'Location', value: network.hosting_country || 'Unknown', icon: '🗺️' },
            { label: 'ISP', value: network.isp || 'Unknown', icon: '🏢' },
            { label: 'Network Risk', value: `${network.network_risk_score}/15`, icon: '⚡', highlight: network.network_risk_score > 5 }
        ];

        networkItems.forEach(item => {
            const div = document.createElement('div');
            div.className = 'feature-item' + (item.highlight ? ' warning' : '');
            div.innerHTML = `
                <span class="feature-icon">${item.icon}</span>
                <div class="feature-content">
                    <span class="feature-label">${item.label}</span>
                    <span class="feature-value">${item.value}</span>
                </div>
            `;
            networkGrid.appendChild(div);
        });

        // Add risk reasons if any
        if (network.risk_reasons && network.risk_reasons.length > 0) {
            const reasonsDiv = document.createElement('div');
            reasonsDiv.className = 'feature-item warning full-width';
            reasonsDiv.innerHTML = `
                <span class="feature-icon">⚠️</span>
                <div class="feature-content">
                    <span class="feature-label">Risk Factors</span>
                    <span class="feature-value">${network.risk_reasons.join(', ')}</span>
                </div>
            `;
            networkGrid.appendChild(reasonsDiv);
        }
    } else {
        document.getElementById('networkSection').classList.add('hidden');
    }

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
