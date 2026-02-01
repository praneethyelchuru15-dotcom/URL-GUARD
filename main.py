import argparse
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import socket
import ssl
from datetime import datetime
import json
import whois
import os
import re
import base64
from dotenv import load_dotenv

load_dotenv()

def analyze_content(html_content, url):
    """
    Analyzes HTML content for suspicious elements.
    """
    soup = BeautifulSoup(html_content, 'html.parser')
    risk_score = 0
    findings = []

    # 1. Suspicious Keywords
    suspicious_keywords = ["login", "password", "verify", "bank", "update account", "confirm"]
    text_content = soup.get_text().lower()
    found_keywords = [kw for kw in suspicious_keywords if kw in text_content]
    
    if found_keywords:
        risk_score += len(found_keywords) * 10
        findings.append(f"Suspicious keywords found: {', '.join(found_keywords)}")

    # 2. External Forms
    forms = soup.find_all('form')
    for form in forms:
        action = form.get('action')
        if action:
            action_url = urljoin(url, action)
            if urlparse(action_url).netloc != urlparse(url).netloc:
                risk_score += 20
                findings.append(f"External form action detected: {action}")

    return {"risk_score": risk_score, "findings": findings}

def check_ip_reputation(url):
    """
    Checks the reputation of the URL's hosting IP.
    """
    risk_score = 0
    findings = []
    
    try:
        hostname = urlparse(url).netloc
        if ':' in hostname:
            hostname = hostname.split(':')[0]
            
        ip_address = socket.gethostbyname(hostname)
        findings.append(f"Resolved IP: {ip_address}")
        
        # Simulated Blacklist
        malicious_ips = ["93.184.216.34", "127.0.0.1"] 
        
        if ip_address in malicious_ips:
            findings.append(f"ALERT: IP {ip_address} is in the BLACKLIST!")
            risk_score += 50
        else:
            findings.append(f"IP {ip_address} seems clean.")
            
    except socket.error as e:
        findings.append(f"Error resolving IP: {e}")

    return {"risk_score": risk_score, "findings": findings}

def check_ssl(url):
    """
    Checks the SSL/TLS certificate validity.
    """
    risk_score = 0
    findings = []
    
    parsed_url = urlparse(url)
    if parsed_url.scheme != 'https':
        findings.append("WARNING: URL is not using HTTPS. Communication is not encrypted.")
        risk_score += 20
        return {"risk_score": risk_score, "findings": findings}
    
    hostname = parsed_url.netloc
    port = 443
    if ':' in hostname:
        hostname, port = hostname.split(':')
        port = int(port)

    context = ssl.create_default_context()
    
    try:
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                # Check expiration
                not_after = datetime.strptime(cert['notAfter'], r'%b %d %H:%M:%S %Y %Z')
                if datetime.utcnow() > not_after:
                    findings.append(f"ALERT: Certificate has EXPIRED on {not_after}")
                    risk_score += 50
                else:
                    days_left = (not_after - datetime.utcnow()).days
                    findings.append(f"Certificate is Valid. Expires in {days_left} days ({not_after}).")
                    
    except ssl.SSLCertVerificationError as e:
        findings.append(f"ALERT: SSL Verification Failed: {e}")
        risk_score += 50
    except Exception as e:
        findings.append(f"Error checking SSL: {e}")
        risk_score += 10
        
    return {"risk_score": risk_score, "findings": findings}

def analyze_headers(response):
    """
    Analyzes HTTP response headers for security issues.
    """
    headers = response.headers
    risk_score = 0
    findings = []

    # 1. Missing Security Headers
    security_headers = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options"
    ]
    
    for header in security_headers:
        if header not in headers:
            findings.append(f"Missing Security Header: {header}")
            risk_score += 10

    # 2. Information Leakage
    leakage_headers = ["Server", "X-Powered-By", "X-AspNet-Version"]
    for header in leakage_headers:
        if header in headers:
            findings.append(f"Information Leakage: {header}: {headers[header]}")
            risk_score += 10

    return {"risk_score": risk_score, "findings": findings}

def scan_ports(url):
    """
    Scans common ports to check for open services.
    """
    risk_score = 0
    findings = []
    
    try:
        hostname = urlparse(url).netloc
        if ':' in hostname:
            hostname = hostname.split(':')[0]
            
        ip_address = socket.gethostbyname(hostname)
        ports = [21, 22, 23, 25, 53, 80, 443, 8080, 3306]
        open_ports = []
        
        findings.append(f"Scanning ports for {ip_address}...")
        
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1) 
            result = sock.connect_ex((ip_address, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
            
        if open_ports:
            findings.append(f"ALERT: Open Ports Found: {open_ports}")
            if 3306 in open_ports or 23 in open_ports or 21 in open_ports:
                risk_score += 30
        else:
            findings.append("No common open ports found (masked or closed).")
            
    except socket.error as e:
        findings.append(f"Error scanning ports: {e}")
        
    return {"risk_score": risk_score, "findings": findings}

def check_whois(url):
    """
    Retrieves and analyzes Whois domain information.
    """
    risk_score = 0
    findings = []
    
    try:
        domain = urlparse(url).netloc
        if ':' in domain:
            domain = domain.split(':')[0]
            
        w = whois.whois(domain)
        
        findings.append(f"Registrar: {w.registrar}")
        
        if w.creation_date:
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if creation_date.tzinfo:
                creation_date = creation_date.replace(tzinfo=None)
                
            age_days = (datetime.now() - creation_date).days
            findings.append(f"Creation Date: {creation_date} (Age: {age_days} days)")
            
            if age_days < 30:
                findings.append(f"ALERT: Domain is very young (< 30 days)!")
                risk_score += 30
        
        if w.expiration_date:
            expiration_date = w.expiration_date
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            findings.append(f"Expiration Date: {expiration_date}")
            
    except Exception as e:
        findings.append(f"Whois Query Failed: {e}")
        
    return {"risk_score": risk_score, "findings": findings}
        
import dns.resolver

def check_dns(url):
    """
    Performs DNS enumeration (A, MX, NS, TXT).
    """
    risk_score = 0
    findings = []
    
    try:
        domain = urlparse(url).netloc
        if ':' in domain:
            domain = domain.split(':')[0]
            
        # 1. A Records
        try:
            answers = dns.resolver.resolve(domain, 'A')
            ips = [r.to_text() for r in answers]
            findings.append(f"A Records: {', '.join(ips)}")
        except Exception:
            findings.append("No A records found.")

        # 2. MX Records
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            mxs = [r.exchange.to_text() for r in answers]
            findings.append(f"MX Records: {', '.join(mxs)}")
        except Exception:
            findings.append("No MX records found (Suspicious for a legitimate domain).")
            risk_score += 20

        # 3. NS Records
        try:
            answers = dns.resolver.resolve(domain, 'NS')
            nss = [r.to_text() for r in answers]
            findings.append(f"NS Records: {', '.join(nss)}")
        except Exception:
            findings.append("No NS records found.")

        # 4. TXT Records
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            txts = [r.to_text() for r in answers]
            security_txt = [t for t in txts if "v=spf1" in t or "v=DMARC1" in t]
            if security_txt:
                 findings.append(f"Security TXT Records: {', '.join(security_txt)}")
            else:
                 findings.append("No SPF/DMARC TXT records found.")
                 risk_score += 10
        except Exception:
             findings.append("No TXT records found.")

    except Exception as e:
        findings.append(f"DNS Query Failed: {e}")
        
    return {"risk_score": risk_score, "findings": findings}

import re

def check_google_safe_browsing(url):
    """
    Checks URL against Google Safe Browsing API (Real-World Threat Intel).
    """
    risk_score = 0
    findings = []
    
    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key:
        findings.append("Skipped: No GOOGLE_API_KEY found in .env file.")
        print("DEBUG: Google API Key missing.")
        return {"risk_score": 0, "findings": findings}

    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    
    payload = {
        "client": {
            "clientId": "url-guard",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": url}
            ]
        }
    }
    
    try:
        print(f"DEBUG: Querying Google Safe Browsing for {url}...")
        response = requests.post(api_url, json=payload, timeout=5)
        print(f"DEBUG: Google API Status: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            if "matches" in result:
                matches = result["matches"]
                threat_types = set(m["threatType"] for m in matches)
                findings.append(f"[CRITICAL] Google flagged this URL as {', '.join(threat_types)}")
                risk_score += 100 
            else:
                findings.append("[SAFE] Google Safe Browsing: No threats found (Clean).")
        else:
            findings.append(f"Error checking Google API: HTTP {response.status_code}")
            
    except Exception as e:
        print(f"DEBUG: Google API Error: {e}")
        findings.append(f"Safe Browsing Connection Failed: {e}")

    return {"risk_score": risk_score, "findings": findings}

def check_url_patterns(url):
    """
    Heuristic: Analyzes the URL string itself for suspicious patterns.
    """
    risk_score = 0
    findings = []
    
    domain = urlparse(url).netloc.lower()
    
    # 1. Suspicious TLDs
    suspicious_tlds = ['.xyz', '.top', '.club', '.win', '.gq', '.cc', '.bd', '.cn']
    if any(domain.endswith(tld) for tld in suspicious_tlds):
        findings.append(f"Suspicious TLD detected: {domain.split('.')[-1]}")
        risk_score += 20
        
    # 2. IP Address as Hostname
    # Regex for IP address
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
        findings.append("URL uses an IP address instead of a domain name (Common in malware).")
        risk_score += 50
        
    # 3. URL Shorteners
    shorteners = ['bit.ly', 'goo.gl', 'tinyurl.com', 'is.gd', 'cli.gs']
    if any(domain == s for s in shorteners):
        findings.append("URL uses a shortening service (High Risk of masking).")
        risk_score += 30
        
    return {"risk_score": risk_score, "findings": findings}

def check_virustotal(url):
    """
    Checks URL against VirusTotal API (v3).
    """
    risk_score = 0
    findings = []
    
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        findings.append("Skipped: No VIRUSTOTAL_API_KEY found in .env file.")
        return {"risk_score": 0, "findings": findings}

    try:
        # VirusTotal v3 requires base64url encoding without padding
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        
        headers = {
            "x-apikey": api_key
        }
        
        print(f"DEBUG: Querying VirusTotal for {url}...")
        response = requests.get(api_url, headers=headers, timeout=5)
        
        if response.status_code == 200:
            data = response.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            
            if malicious > 0:
                findings.append(f"[CRITICAL] VirusTotal flagged this URL as MALICIOUS ({malicious} engines).")
                risk_score += 100
            elif suspicious > 0:
                findings.append(f"VirusTotal flagged this URL as SUSPICIOUS ({suspicious} engines).")
                risk_score += 50
            else:
                findings.append(f"[SAFE] VirusTotal: Clean ({stats.get('harmless', 0)} engines).")
                
        elif response.status_code == 404:
            findings.append("VirusTotal: URL not found in database (New/Unknown).")
        else:
            findings.append(f"Error checking VirusTotal: HTTP {response.status_code}")
            
    except Exception as e:
        print(f"DEBUG: VirusTotal Error: {e}")
        findings.append(f"VirusTotal Connection Failed: {e}")

    return {"risk_score": risk_score, "findings": findings}

    return {"risk_score": risk_score, "findings": findings}

def generate_recommendations(report):
    """
    Generates actionable security advice based on scan findings.
    """
    recommendations = []
    
    # 1. Headers
    headers_module = report["modules"].get("HTTP Headers", {})
    if any("Missing Security Header" in f for f in headers_module.get("findings", [])):
        recommendations.append("Add missing security headers (HSTS, CSP, X-Frame-Options) to your server configuration.")
        
    # 2. Ports
    ports_module = report["modules"].get("Port Scan", {})
    open_ports_finding = next((f for f in ports_module.get("findings", []) if "Open Ports Found" in f), None)
    if open_ports_finding:
        if "21" in open_ports_finding:
            recommendations.append("Close Port 21 (FTP) immediately if not explicitly needed. Use SFTP instead.")
        if "23" in open_ports_finding:
            recommendations.append("Close Port 23 (Telnet). It is insecure. Use SSH (Port 22) instead.")
            
    # 3. DNS
    dns_module = report["modules"].get("DNS Intelligence", {})
    findings = dns_module.get("findings", [])
    if any("No MX records" in f for f in findings) or any("No SPF/DMARC" in f for f in findings):
        recommendations.append("Add DNS TXT (SPF/DMARC) and MX records to establish domain legitimacy and prevent spoofing.")
        
    # 4. SSL
    ssl_module = report["modules"].get("SSL Check", {})
    if any("EXPIRED" in f for f in ssl_module.get("findings", [])) or any("not using HTTPS" in f for f in ssl_module.get("findings", [])):
        recommendations.append("Renew or Install a valid SSL Certificate to enable HTTPS.")

    if not recommendations:
        recommendations.append("Great job! No critical configuration issues detected.")
        
    return recommendations

def scan_url(url):
    """
    Run all scans and return a comprehensive report.
    """
    start_time = datetime.now()
    report = {
        "url": url,
        "timestamp": str(start_time),
        "status_code": None,
        "total_risk_score": 0,
        "scan_duration_seconds": 0,
        "modules": {},
        "recommendations": []
    }
    
    print(f"Scanning {url}...")
    
    # 1. Infrastructure Checks (Do not require HTTP 200)
    # These checks are vital even if the site is down or blocking us
    modules = {
        "Google Threat Intel": check_google_safe_browsing(url), 
        "VirusTotal": check_virustotal(url),
        "URL Patterns": check_url_patterns(url),
        "IP Reputation": check_ip_reputation(url),
        "Whois Lookup": check_whois(url),
        "DNS Intelligence": check_dns(url),
        "SSL Check": check_ssl(url),
        "Port Scan": scan_ports(url)
    }

    # 2. HTTP Content Checks
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=5)
        report["status_code"] = response.status_code
        
        modules["HTTP Headers"] = analyze_headers(response)
        
        if response.status_code == 200:
            modules["Content Analysis"] = analyze_content(response.text, url)
        else:
            modules["Content Analysis"] = {"risk_score": 0, "findings": [f"Skipped: HTTP Status {response.status_code}"]}

    except requests.exceptions.RequestException as e:
        print(f"Error scanning URL: {e}")
        report["error"] = str(e)
        modules["Content Analysis"] = {"risk_score": 0, "findings": ["Skipped: Connection Failed"]}
        modules["HTTP Headers"] = {"risk_score": 0, "findings": ["Skipped: No Response"]}

    report["modules"] = modules
    report["total_risk_score"] = sum(m["risk_score"] for m in modules.values())
    
    # Generate Recommendations and calculate time
    report["recommendations"] = generate_recommendations(report)
    
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    report["scan_duration_seconds"] = round(duration, 2)
        
    return report

def print_report(report):
    """
    Prints the report to CLI.
    """
    if "error" in report:
        print(f"Scan failed: {report['error']}")
        return

    print(f"\nScan complete for {report['url']}")
    print(f"Status Code: {report['status_code']}")
    print(f"Total Risk Score: {report['total_risk_score']}")
    print(f"Time Taken: {report['scan_duration_seconds']} seconds")
    
    if report.get("recommendations"):
        print(f"\n--- [ACTION REQUIRED] SECURITY RECOMMENDATIONS ---")
        for rec in report["recommendations"]:
            print(f"- {rec}")
    
    for name, data in report["modules"].items():
        print(f"\n--- {name} ---")
        if data["findings"]:
            for f in data["findings"]:
                print(f"- {f}")
            if data["risk_score"] > 0:
                print(f"Risk Score Increase: {data['risk_score']}")
        else:
            print("No issues found.")

def main():
    parser = argparse.ArgumentParser(description="Network Security Tool - URL Guard")
    parser.add_argument("url", help="The URL to scan")
    parser.add_argument("--output", help="Save results to a JSON file")
    args = parser.parse_args()

    print("Starting URL Guard...")
    report = scan_url(args.url)
    print_report(report)
    
    if args.output:
        try:
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=4, default=str)
            print(f"\nReport saved to {args.output}")
        except Exception as e:
            print(f"Error saving report: {e}")

if __name__ == "__main__":
    main()
