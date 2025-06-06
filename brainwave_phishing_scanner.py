# brainwave_phishing_scanner.py
import re
import requests
import validators
from urllib.parse import urlparse

PHISHING_KEYWORDS = ['secure', 'account', 'webscr', 'login', 'signin', 'update', 'verify', 'banking', 'confirm']

def is_ip_address(url):
    return bool(re.match(r'^https?://\d{1,3}(\.\d{1,3}){3}', url))

def has_phishing_keywords(url):
    return any(keyword in url.lower() for keyword in PHISHING_KEYWORDS)

def is_shortened(url):
    shortened_domains = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly']
    parsed = urlparse(url)
    return parsed.netloc in shortened_domains

def check_ssl(url):
    try:
        response = requests.get(url, timeout=5)
        return response.url.startswith("https")
    except:
        return False

def analyze_url(url):
    results = {
        "valid_url": validators.url(url),
        "is_ip_based": is_ip_address(url),
        "contains_phishing_keywords": has_phishing_keywords(url),
        "is_shortened": is_shortened(url),
        "uses_https": check_ssl(url)
    }

    red_flags = sum([
        results["is_ip_based"],
        results["contains_phishing_keywords"],
        results["is_shortened"],
        not results["uses_https"]
    ])

    results["verdict"] = "⚠️ Suspicious" if red_flags >= 2 else "✅ Safe (but always double-check)"
    return results

if __name__ == "__main__":
    print("🔍 Brainwave Matrix - Phishing Link Scanner")
    url = input("Enter a URL to scan: ").strip()

    report = analyze_url(url)
    print("\n--- Scan Results ---")
    for key, value in report.items():
        print(f"{key.replace('_', ' ').capitalize()}: {value}")
