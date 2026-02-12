
import sys
import os
from urllib.parse import urlparse

# Mimic app.py setup
sys.path.append('backend')
sys.path.append('backend/Network_Validator')

try:
    from backend.Network_Validator.network.network_validator import network_scan
except ImportError:
    # Try local import if running from root
    sys.path.append('backend/Network_Validator')
    from network.network_validator import network_scan

def test_url(url):
    print(f"\n--- Testing URL: {url} ---")
    try:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path.split('/')[0]
        print(f"Parsed Domain: '{domain}'")
        
        results = network_scan(domain)
        print("Network Scan Results:")
        for k, v in results.items():
            print(f"  {k}: {v}")
            
    except Exception as e:
        print(f"Error: {e}")

urls_to_test = [
    "https://google.com",
    "http://google.com",
    "google.com",
    "https://www.google.com/search?q=test",
    "http://142.250.77.142",
    "https://microsoft.com",
    "http://google.com:80",
    "https://google.com:443/search",
    "http://127.0.0.1:5000"
]

if __name__ == "__main__":
    for url in urls_to_test:
        test_url(url)
