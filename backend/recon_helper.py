import whois
import dns.resolver
import ssl
import socket
import requests
import time
import logging
import re
from datetime import datetime

LOGGER = logging.getLogger(__name__)

def validate_hostname(hostname):
    """Ensure hostname contains only allowed characters."""
    if not hostname:
        return False
    return bool(re.match(r'^[a-zA-Z0-9.-]+$', str(hostname)))


def _as_single_date(value):
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _lookup_whois(domain):
    # Support multiple whois package APIs across environments.
    whois_fn = getattr(whois, "whois", None)
    if callable(whois_fn):
        return whois_fn(domain)
    query_fn = getattr(whois, "query", None)
    if callable(query_fn):
        return query_fn(domain)
    raise AttributeError("No supported WHOIS lookup function found in whois module")


def _safe_attr(obj, name, default="N/A"):
    value = getattr(obj, name, default)
    return value if value not in (None, "", []) else default


def get_whois_info(domain):
    if not validate_hostname(domain):
        return {"error": "Invalid domain format"}
    try:
        w = _lookup_whois(domain)
        return {
            "domain_name": _safe_attr(w, "domain_name"),
            "registrar": _safe_attr(w, "registrar"),
            "creation_date": str(_as_single_date(_safe_attr(w, "creation_date", None))),
            "expiration_date": str(_as_single_date(_safe_attr(w, "expiration_date", None))),
            "org": _safe_attr(w, "org"),
        }
    except Exception:
        LOGGER.warning("WHOIS lookup failed for domain: %s", domain)
        return {"error": "Whois lookup failed"}

def get_dns_records(domain):
    if not validate_hostname(domain):
        return {"error": "Invalid domain format"}
    records = {}
    for rtype in ['A', 'MX', 'NS', 'TXT']:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records[rtype] = [str(r) for r in answers]
        except Exception:
            LOGGER.debug("DNS lookup failed for %s record on %s", rtype, domain)
            records[rtype] = []
    return records

def get_ssl_details(hostname):
    if not validate_hostname(hostname):
        return {"status": "UNAVAILABLE", "error": "Invalid hostname"}
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
    except OSError as e:
        LOGGER.warning("SSL socket check failed for host %s: %s", hostname, e)
        return {"status": "UNAVAILABLE", "error": "No SSL/HTTPS detected"}
    except Exception:
        LOGGER.warning("SSL details fetch failed for host: %s", hostname)
        return {"status": "UNAVAILABLE", "error": "No SSL/HTTPS detected"}

def get_geo_info(hostname):
    if not validate_hostname(hostname):
        return {"error": "Invalid hostname"}
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
    except Exception:
        LOGGER.warning("Geo lookup failed for host: %s", hostname)
        return {"error": "Geolocation failed"}

def get_server_health(url):
    """Measures load time and responsiveness"""
    # Extract host to validate
    from urllib.parse import urlparse
    parsed = urlparse(url if "://" in url else f"http://{url}")
    host = parsed.hostname or url.split('/')[0]
    if not validate_hostname(host):
        return {"error": "Invalid URL format"}
        
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
    except Exception:
        LOGGER.warning("Server health check failed for url: %s", url)
        return {"error": "Server health check failed"}

def get_tech_stack(url):
    # Extract host to validate
    from urllib.parse import urlparse
    parsed = urlparse(url if "://" in url else f"http://{url}")
    host = parsed.hostname or url.split('/')[0]
    if not validate_hostname(host):
        return {"error": "Invalid URL format"}
        
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
    except Exception:
        LOGGER.warning("Tech stack profiling failed for url: %s", url)
        return {"error": "Tech profiling failed"}
