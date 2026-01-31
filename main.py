import argparse
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import socket
import ssl
from datetime import datetime
import json
import whois

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
            if 3306 in open_ports or 23 in open_ports:
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

def scan_url(url):
    """
    Run all scans and return a comprehensive report.
    """
    report = {
        "url": url,
        "timestamp": str(datetime.now()),
        "status_code": None,
        "total_risk_score": 0,
        "modules": {}
    }
    
    print(f"Scanning {url}...")
    try:
        response = requests.get(url, timeout=5)
        report["status_code"] = response.status_code
        
        if response.status_code == 200:
            modules = {
                "Content Analysis": analyze_content(response.text, url),
                "IP Reputation": check_ip_reputation(url),
                "SSL Check": check_ssl(url),
                "HTTP Headers": analyze_headers(response),
                "Port Scan": scan_ports(url),
                "Whois Lookup": check_whois(url)
            }
            
            report["modules"] = modules
            report["total_risk_score"] = sum(m["risk_score"] for m in modules.values())
            
    except requests.exceptions.RequestException as e:
        print(f"Error scanning URL: {e}")
        report["error"] = str(e)
        
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
