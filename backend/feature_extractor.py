"""
URL Feature Extractor for Phishing Detection
Extracts various features from URLs to identify potential phishing attempts
"""

import re
from urllib.parse import urlparse
import tldextract
import validators


class URLFeatureExtractor:
    """Extract features from URLs for ML classification"""
    
    def __init__(self):
        # Common phishing keywords
        self.suspicious_keywords = [
            'login', 'signin', 'account', 'update', 'secure', 'verify', 
            'banking', 'paypal', 'ebay', 'amazon', 'microsoft', 'apple',
            'confirm', 'suspended', 'restricted', 'unusual', 'click'
        ]
        
    def extract_features(self, url):
        """Extract all features from a URL"""
        
        # Validate URL
        if not validators.url(url):
            # Try adding http:// prefix
            url = 'http://' + url
            if not validators.url(url):
                raise ValueError("Invalid URL format")
        
        features = {}
        parsed_url = urlparse(url)
        extracted = tldextract.extract(url)
        
        # Basic URL features
        features['url_length'] = len(url)
        features['domain_length'] = len(extracted.domain)
        
        # Protocol features
        features['has_https'] = 1 if parsed_url.scheme == 'https' else 0
        features['has_http'] = 1 if parsed_url.scheme == 'http' else 0
        
        # Domain features
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_underscores'] = url.count('_')
        features['num_slashes'] = url.count('/')
        features['num_question_marks'] = url.count('?')
        features['num_equal_signs'] = url.count('=')
        features['num_at_symbols'] = url.count('@')
        features['num_ampersands'] = url.count('&')
        
        # Suspicious pattern detection
        features['has_ip_address'] = 1 if self._has_ip_address(url) else 0
        features['num_subdomain_levels'] = len(extracted.subdomain.split('.')) if extracted.subdomain else 0
        
        # Length ratios
        features['path_length'] = len(parsed_url.path)
        features['query_length'] = len(parsed_url.query) if parsed_url.query else 0
        
        # Suspicious keywords
        features['num_suspicious_keywords'] = sum(1 for keyword in self.suspicious_keywords if keyword in url.lower())
        
        # Special character density
        special_chars = sum(1 for char in url if not char.isalnum())
        features['special_char_ratio'] = special_chars / len(url) if len(url) > 0 else 0
        
        # Digit ratio
        digits = sum(1 for char in url if char.isdigit())
        features['digit_ratio'] = digits / len(url) if len(url) > 0 else 0
        
        # TLD features
        features['tld_length'] = len(extracted.suffix)
        features['has_suspicious_tld'] = 1 if extracted.suffix in ['tk', 'ml', 'ga', 'cf', 'gq'] else 0
        
        # Domain name entropy (randomness)
        features['domain_entropy'] = self._calculate_entropy(extracted.domain)
        
        return features
    
    def _has_ip_address(self, url):
        """Check if URL contains an IP address instead of domain name"""
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        return bool(re.search(ip_pattern, url))
    
    def _calculate_entropy(self, text):
        """Calculate Shannon entropy of text"""
        if not text:
            return 0
        
        from collections import Counter
        import math
        
        length = len(text)
        counter = Counter(text)
        entropy = 0
        
        for count in counter.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def get_feature_names(self):
        """Return list of feature names in order"""
        return [
            'url_length', 'domain_length', 'has_https', 'has_http',
            'num_dots', 'num_hyphens', 'num_underscores', 'num_slashes',
            'num_question_marks', 'num_equal_signs', 'num_at_symbols',
            'num_ampersands', 'has_ip_address', 'num_subdomain_levels',
            'path_length', 'query_length', 'num_suspicious_keywords',
            'special_char_ratio', 'digit_ratio', 'tld_length',
            'has_suspicious_tld', 'domain_entropy'
        ]
