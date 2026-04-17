import nmap
import requests
import re
import socket
import subprocess
import json
import os
import logging
from urllib.parse import urlparse

LOGGER = logging.getLogger(__name__)

class VulnerabilityScanner:
    def __init__(self):
        # Initialize Nmap Port Scanner if the system nmap binary is available.
        self.nm = None
        self.nmap_error = ""
        try:
            self.nm = nmap.PortScanner()
        except Exception as e:
            self.nmap_error = str(e)
            LOGGER.warning("Nmap scanner initialization failed: %s", e)
        self.fallback_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080]
        self.port_service_map = {
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            143: "imap",
            443: "https",
            445: "smb",
            3306: "mysql",
            3389: "rdp",
            5432: "postgresql",
            8080: "http-proxy",
        }
        # Common Subdomain List
        self.common_subdomains = ["www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "web", "ns2", "api", "dev", "test", "stage", "blog", "shop", "admin", "vpn", "secure", "proxy"]

    def _validate_host(self, host):
        """Strict validation for hostname/IP."""
        if not host:
            return False
        # Prevent command injection characters or path traversal
        return bool(re.match(r'^[a-zA-Z0-9.-]+$', host))

    def _extract_host(self, target):
        if not target:
            return ""
        if "://" in target:
            parsed = urlparse(target)
            host = parsed.hostname or target
        else:
            host = target.split("/")[0]
        
        # Clean port if present in host (e.g. 127.0.0.1:8080)
        if ":" in host:
            host = host.split(":")[0]
        return host

    def _fallback_tcp_scan(self, host, timeout=0.8):
        """Fallback scan for environments where nmap binary is unavailable."""
        results = []
        if not host:
            return results

        for port in self.fallback_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            try:
                if sock.connect_ex((host, port)) == 0:
                    service_name = self.port_service_map.get(port, "unknown")
                    risk_level = "Low (Fallback Scan)"
                    if service_name in ("ftp", "telnet", "rdp"):
                        risk_level = "High (Insecure/Exposed Service)"
                    results.append({
                        "port": port,
                        "protocol": "tcp",
                        "service": service_name,
                        "product": "N/A (fallback-scan)",
                        "version": "N/A",
                        "risk_level": risk_level,
                        "cves": [],
                    })
            except Exception:
                continue
            finally:
                try:
                    sock.close()
                except Exception:
                    pass
        return results

    def run_nuclei(self, target, templates="cves,default-logins,exposed-panels,vulnerabilities"):
        """ Runs Nuclei scanner with AI-suggested templates """
        host = self._extract_host(target)
        if not self._validate_host(host):
            LOGGER.warning("Invalid host for Nuclei: %s", host)
            return []
            
        print(f"[*] Starting Deep Vulnerability Scan with Nuclei: {target} using templates: {templates}")
        
        try:
            # Check if nuclei is installed by running version check
            subprocess.run(["nuclei", "--version"], capture_output=True, check=True)
            
            process = subprocess.run(
                ["nuclei", "-u", host, "-jsonl", "-silent", "-nc", "-t", templates, "-severity", "medium,high,critical"],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            nuclei_findings = []
            if process.stdout:
                lines = process.stdout.strip().split("\n")
                for line in lines:
                    try:
                        data = json.loads(line)
                        nuclei_findings.append({
                            "port": data.get("port", "N/A"),
                            "protocol": "tcp",
                            "service": "nuclei-finding",
                            "product": data.get("info", {}).get("name", "Unknown Vuln"),
                            "version": data.get("info", {}).get("severity", "Low"),
                            "risk_level": f"Nuclei: {data.get('info', {}).get('severity', 'Medium').upper()}",
                            "remediation": data.get("info", {}).get("description", "Refer to template documentation."),
                            "cves": data.get("info", {}).get("classification", {}).get("cve-id", [])
                        })
                    except:
                        continue
            
            return nuclei_findings

        except Exception as e:
            LOGGER.warning("Nuclei not found or failed for target %s: %s", target, e)
            return []

    def enumerate_subdomains(self, domain):
        """ Checks for common subdomains using DNS resolution """
        found_subdomains = []
        print(f"[*] Enumerating Subdomains for: {domain}")
        
        # Simple DNS brute-force
        for sub in self.common_subdomains:
            target_sub = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(target_sub)
                found_subdomains.append({
                    "subdomain": target_sub,
                    "ip": ip
                })
            except socket.gaierror:
                pass # Subdomain not found
        
        return found_subdomains

    def check_web_headers(self, target):
        """ Checks for missing security headers on Port 80/443 """
        findings = []
        host = self._extract_host(target)
        if not self._validate_host(host):
            return findings
            
        try:
            # Handle URL formatting
            if not target.startswith("http"):
                url = f"http://{target}"
            else:
                url = target
                
            print(f"[*] Checking Web Headers for: {url}")
            
            response = requests.get(url, timeout=5)
            headers = response.headers
            
            missing = []
            if 'X-Frame-Options' not in headers:
                missing.append("Missing X-Frame-Options (Clickjacking Risk)")
            if 'Content-Security-Policy' not in headers:
                missing.append("Missing CSP (XSS Risk)")
            if 'Strict-Transport-Security' not in headers:
                missing.append("Missing HSTS (Man-in-the-Middle Risk)")
            if 'X-Content-Type-Options' not in headers:
                missing.append("Missing X-Content-Type-Options (MIME Sniffing Risk)")

            if missing:
                findings.append({
                    "port": 80,
                    "protocol": "tcp",
                    "service": "http-web-config",
                    "product": "Web Server",
                    "version": "N/A",
                    "risk_level": "Medium (Misconfiguration)",
                    "remediation": "Configure server to send security headers: " + ", ".join(missing),
                    "cves": []
                })
        except Exception as e:
            LOGGER.debug("Web header check failed for %s: %s", target, e)
        
        return findings

    def scan_target(self, target, arguments='-sV --script vuln -T4'):
        host = self._extract_host(target)
        if not self._validate_host(host):
            LOGGER.warning("Invalid host for Nmap: %s", host)
            return []
            
        print(f"[*] Starting Deep Vulnerability Scan on: {target} with args: {arguments}")
        if self.nm is None:
            LOGGER.warning("Using fallback TCP scan because nmap is unavailable for target: %s", host)
            return self._fallback_tcp_scan(host)
        
        try:
            self.nm.scan(target, arguments=arguments)
            scan_results = []
            
            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        service_data = self.nm[host][proto][port]
                        
                        service_name = service_data.get('name', 'unknown')
                        version = service_data.get('version', '')
                        product = service_data.get('product', '')
                        
                        # Extract CVEs from Script Output
                        cve_list = []
                        script_outputs = service_data.get('script', {})
                        for output in script_outputs.values():
                            if "CVE-" in output:
                                cves = re.findall(r'CVE-\d{4}-\d{4,7}', output)
                                cve_list.extend(cves)
                        
                        cve_list = list(set(cve_list))
                        
                        # Determine Risk
                        risk_level = "Low"
                        if len(cve_list) > 0:
                            risk_level = "CRITICAL (CVEs Found)"
                        elif "ftp" in service_name or "telnet" in service_name:
                            risk_level = "High (Insecure Protocol)"
                        
                        scan_results.append({
                            "port": port,
                            "protocol": proto,
                            "service": service_name,
                            "product": product,
                            "version": version,
                            "risk_level": risk_level,
                            "cves": cve_list
                        })
                        
            return scan_results

        except Exception as e:
            LOGGER.exception("Nmap scan failed for %s: %s", target, e)
            raise
