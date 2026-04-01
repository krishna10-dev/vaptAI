import nmap
import requests
import re
import socket
import subprocess
import json
import os

class VulnerabilityScanner:
    def __init__(self):
        # Initialize Nmap Port Scanner
        self.nm = nmap.PortScanner()
        # Common Subdomain List
        self.common_subdomains = ["www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "web", "ns2", "api", "dev", "test", "stage", "blog", "shop", "admin", "vpn", "secure", "proxy"]

    def run_nuclei(self, target, templates="cves,default-logins,exposed-panels,vulnerabilities"):
        """ Runs Nuclei scanner with AI-suggested templates """
        print(f"[*] Starting Deep Vulnerability Scan with Nuclei: {target} using templates: {templates}")
        
        # Ensure target is just the host for Nuclei
        host = target.replace("http://", "").replace("https://", "").split("/")[0]
        
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
            print(f"⚠️ Nuclei not found or failed: {e}")
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
            # It's common for non-web servers to fail here, just ignore
            pass
        
        return findings

    def scan_target(self, target, arguments='-sV --script vuln -T4'):
        print(f"[*] Starting Deep Vulnerability Scan on: {target} with args: {arguments}")
        
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
            print(f"Error during scan: {e}")
            return []