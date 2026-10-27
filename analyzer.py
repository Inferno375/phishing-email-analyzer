import email
from email import policy
import re
import hashlib

# Threat Intel & Whitelist Databases
KNOWN_BAD_IPS = ['203.0.113.42', '198.51.100.77']
KNOWN_BAD_URLS = ['http://evil-phishing-link.com/login', 'http://malware-download.com/exe']
KNOWN_BAD_HASHES = ['8c6680bc944747eb10b7b62b323c21a16629ed3e53ef711b7dfb086ec44deec5']
KNOWN_GOOD_IPS = ['10.0.0.5', '127.0.0.1']

SUSPICIOUS_EXTENSIONS = ['.exe', '.scr', '.vbs', '.bat', '.ps1', '.zip']

def extract_urls(text):
    url_pattern = r'https?://[^\s<>"]+'
    return re.findall(url_pattern, text)

def extract_ips(text):
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    return re.findall(ip_pattern, text)

def extract_domain(email_address):
    """Strips an email address down to just its domain (e.g. admin@paypal.com -> paypal.com)"""
    if email_address and '@' in str(email_address):
        return str(email_address).split('@')[-1].strip('>').lower()
    return ""

def parse_email(file_path):
    risk_score = 0
    flagged_reasons = []

    with open(file_path, 'rb') as f:
        msg = email.message_from_binary_file(f, policy=policy.default)

    # 1. Header Analysis & Spoof Check
    from_header = msg.get('From', '')
    return_path = msg.get('Return-Path', '')
    
    from_domain = extract_domain(from_header)
    return_domain = extract_domain(return_path)

    if from_domain and return_domain and from_domain != return_domain:
        risk_score += 30
        flagged_reasons.append(f"Header Mismatch: From ({from_domain}) != Return-Path ({return_domain})")

    # 2. IP Routing Analysis
    for header in msg.get_all('Received', []):
        for ip in extract_ips(header):
            if ip in KNOWN_GOOD_IPS:
                continue
            if ip in KNOWN_BAD_IPS:
                risk_score += 40
                flagged_reasons.append(f"Blacklisted IP Detected: {ip}")

    # 3. URL Extraction & Analysis
    for part in msg.walk():
        if part.get_content_type() == "text/plain":
            for url in extract_urls(part.get_content()):
                if url in KNOWN_BAD_URLS:
                    risk_score += 40
                    flagged_reasons.append(f"Blacklisted URL Detected: {url}")

    # 4. Attachment Analysis
    for part in msg.walk():
        filename = part.get_filename()
        if filename:
            # Extension check
            if any(filename.lower().endswith(ext) for ext in SUSPICIOUS_EXTENSIONS):
                risk_score += 20
                flagged_reasons.append(f"Suspicious Attachment Extension: {filename}")

            # Hash check
            file_data = part.get_payload(decode=True)
            if file_data:
                file_hash = hashlib.sha256(file_data).hexdigest()
                if file_hash in KNOWN_BAD_HASHES:
                    risk_score += 50
                    flagged_reasons.append(f"Known Malware Hash Detected: {file_hash}")

    # Determine Verdict
    if risk_score >= 50:
        verdict = "MALICIOUS"
    elif risk_score >= 20:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    # --- Executive Summary Output ---
    print("=" * 50)
    print("       PHISHING EMAIL ANALYSIS REPORT       ")
    print("=" * 50)
    print(f"Subject:     {msg.get('Subject')}")
    print(f"From:        {from_header}")
    print(f"Return-Path: {return_path}")
    print("-" * 50)
    print(f"FINAL VERDICT: [ {verdict} ]")
    print(f"RISK SCORE:    {risk_score} / 100")
    print("-" * 50)
    print("DETECTION DETAILS:")
    if flagged_reasons:
        for reason in flagged_reasons:
            print(f"  [!] {reason}")
    else:
        print("  [+] No threat indicators detected.")
    print("=" * 50)

parse_email('test_email.eml')