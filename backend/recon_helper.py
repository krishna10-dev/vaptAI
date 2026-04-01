import whois
import dns.resolver
import ssl
import socket
import requests
import time
from datetime import datetime

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        return {
            "registrar": w.registrar,
            "creation_date": str(w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date),
            "expiration_date": str(w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date),
            "org": w.org or "N/A"
        }
    except:
        return {"error": "Whois lookup failed"}

def get_dns_records(domain):
    records = {}
    for rtype in ['A', 'MX', 'NS', 'TXT']:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records[rtype] = [str(r) for r in answers]
        except:
            records[rtype] = []
    return records

def get_ssl_details(hostname):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                subject = dict(x[0] for x in cert['subject'])
                issuer = dict(x[0] for x in cert['issuer'])
                
                notAfter = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_left = (notAfter - datetime.now()).days
                
                return {
                    "common_name": subject.get('commonName'),
                    "issuer": issuer.get('organizationName'),
                    "version": ssock.version(),
                    "cipher": ssock.cipher()[0],
                    "expiry": cert['notAfter'],
                    "days_remaining": days_left,
                    "status": "SECURE" if days_left > 0 else "EXPIRED",
                    "grade": "A" if days_left > 90 else "B"
                }
    except:
        return {"status": "UNAVAILABLE", "error": "No SSL/HTTPS detected"}

def get_geo_info(hostname):
    try:
        ip = socket.gethostbyname(hostname)
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
        return {
            "ip": ip,
            "country": res.get("country"),
            "city": res.get("city"),
            "isp": res.get("isp"),
            "lat": res.get("lat"),
            "lon": res.get("lon")
        }
    except:
        return {"error": "Geolocation failed"}

def get_server_health(url):
    """Measures load time and responsiveness"""
    try:
        if not url.startswith("http"): url = "http://" + url
        start = time.time()
        res = requests.get(url, timeout=10, verify=False)
        end = time.time()
        
        latency = round((end - start) * 1000, 2)
        
        # Simple Header Grading
        h = res.headers
        security_headers = ["Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Strict-Transport-Security"]
        found = [sh for sh in security_headers if sh in h]
        
        grade = "F"
        if len(found) == 4: grade = "A"
        elif len(found) == 3: grade = "B"
        elif len(found) == 2: grade = "C"
        elif len(found) == 1: grade = "D"

        return {
            "latency_ms": latency,
            "status_code": res.status_code,
            "security_grade": grade,
            "missing_headers": [sh for sh in security_headers if sh not in h]
        }
    except:
        return {"error": "Server health check failed"}

def get_tech_stack(url):
    try:
        if not url.startswith("http"): url = "http://" + url
        response = requests.get(url, timeout=5, verify=False)
        headers = response.headers
        server = headers.get("Server", "Unknown")
        
        techs = []
        if "nginx" in server.lower(): techs.append("Nginx")
        if "apache" in server.lower(): techs.append("Apache")
        if "cloudflare" in server.lower(): techs.append("Cloudflare")
        if "express" in server.lower(): techs.append("Node.js/Express")
        
        return {
            "server": server,
            "detected_techs": techs,
            "powered_by": headers.get("X-Powered-By", "Hidden")
        }
    except:
        return {"error": "Tech profiling failed"}
