import re
import socket
import joblib
import requests
import whois
import pandas as pd
import tldextract
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from flask import Flask, request, jsonify
from flask_cors import CORS

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for cross-origin requests

# Load trained model
model = joblib.load("Trained_Models/Final_Grid_model2.pkl")

# Get expected feature names from the model
feature_names = model.feature_names_in_

def get_domain(url):
    """Extracts the domain name from the URL."""
    parsed_url = urlparse(url)
    return parsed_url.netloc

def get_subdomain_count(domain):
    """Counts the number of subdomains."""
    return len(domain.split(".")) - 2 if domain.count(".") > 1 else -1

def get_domain_age(domain):
    """Fetches domain registration age using WHOIS."""
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        expiration_date = domain_info.expiration_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        domain_age = (expiration_date - creation_date).days / 365 if creation_date and expiration_date else -1
        return 1 if domain_age > 1 else -1
    except:
        return -1  # Use -1 instead of 0 for missing data

def check_dns(domain):
    """Checks if the domain has a valid DNS record."""
    try:
        socket.gethostbyname(domain)
        return 1  # DNS record exists
    except socket.gaierror:
        return -1  # No DNS record

def check_favicon(url):
    """Checks if the website has a favicon."""
    try:
        response = requests.get(url, timeout=3)
        soup = BeautifulSoup(response.text, "html.parser")
        favicon = soup.find("link", rel="icon")
        return 1 if favicon else -1
    except:
        return -1  # No favicon found

def count_external_links(url, domain):
    """Counts the number of external links on the webpage."""
    try:
        response = requests.get(url, timeout=3)
        soup = BeautifulSoup(response.text, "html.parser")
        links = [a["href"] for a in soup.find_all("a", href=True)]
        
        external_links = [link for link in links if not link.startswith("/") and domain not in link]
        return 1 if len(external_links) > 5 else -1
    except:
        return -1  # Default if request fails

def check_port(domain, port=80):
    """Checks if a common web port is open."""
    try:
        with socket.create_connection((domain, port), timeout=2):
            return 1  # Port is open
    except:
        return -1  # Port is closed

def extract_url_features(url):
    """
    Extracts features from a URL to match the dataset structure.
    """
    # Ensure URL has a scheme
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    extracted = tldextract.extract(url)
    subdomain = extracted.subdomain
    domain = extracted.domain

    # Feature extraction
    features = {
        "having_IPhaving_IP_Address": 2 if re.match(r"(\d{1,3}\.){3}\d{1,3}", url) else -1,
        "URLURL_Length": 1 if len(url) > 75 else -1,
        "Shortining_Service": 1.5 if any(short in url for short in ["bit.ly", "goo.gl", "tinyurl"]) else -1,
        "having_At_Symbol": 2 if "@" in url else -1,
        "double_slash_redirecting": 1 if "//" in url[7:] else -1,
        "Prefix_Suffix": 1 if "-" in domain else -1,
        "having_Sub_Domain": get_subdomain_count(domain),
        "SSLfinal_State": -0.5 if url.startswith("https://") else 1,
        "Domain_registeration_length": get_domain_age(domain),
        "Favicon": check_favicon(url),
        "port": check_port(domain, 443),
        "HTTPS_token": 1 if "https" in domain else -1,
        "Request_URL": 1 if "external" in url.lower() else -1,
        "URL_of_Anchor": count_external_links(url, domain),
        "Links_in_tags": count_external_links(url, domain),
        "SFH": -1,  
        "Submitting_to_email": 1 if "mailto:" in url else -1,
        "Abnormal_URL": 1 if domain not in url else -1,
        "Redirect": 1 if url.count("//") > 2 else -1,
        "on_mouseover": 1,  
        "RightClick": 1,  
        "popUpWidnow": 1,  
        "Iframe": 1,  
        "age_of_domain": get_domain_age(domain),
        "DNSRecord": check_dns(domain),
        "web_traffic": -1,  
        "Page_Rank": -1,  
        "Google_Index": -1,  
        "Links_pointing_to_page": 1,  
        "Statistical_report": -1,  
    }

    df = pd.DataFrame([features])
    for feature in feature_names:
        if feature not in df.columns:
            df[feature] = -1  
    
    return df[feature_names]

@app.route('/api/predict-url', methods=['POST'])
def predict_url():
    data = request.json
    if not data or 'url' not in data:
        return jsonify({'error': 'URL is required'}), 400
    
    url = data['url'].strip()
    features = extract_url_features(url)
    prediction = model.predict(features)[0]
    phish_probability = model.predict_proba(features)[0][1]
    legit_probability = 1 - phish_probability

    if phish_probability >= 0.50:
        result = "PHISHING"
        warning = "🚨 Unsafe — the model predicts this is a phishing site"
    elif phish_probability >= 0.20:
        result = "SUSPICIOUS"
        warning = "⚠️ Proceed with caution — suspicious characteristics detected"
    else:
        result = "LEGITIMATE"
        warning = "✅ Safe to proceed"

    return jsonify({
        'URL': url,
        'Prediction': result,
        'Legitimate Confidence': f"{legit_probability:.2%}",
        'Phishing Confidence': f"{phish_probability:.2%}",
        'Warning Level': warning
    })


if __name__ == '__main__':
    app.run(port=5000)
