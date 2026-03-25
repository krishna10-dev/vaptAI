def get_remediation(service, port, risk):
    service = str(service).lower()
    risk = str(risk).lower()
    
    # Default Advice
    advice = "Ensure the service is patched to the latest stable version and restrict access via Firewall."

    # Specific Logic based on Port/Service
    if "telnet" in service or port == 23:
        advice = "CRITICAL: Disable Telnet immediately. It transmits credentials in cleartext. Switch to SSH (Port 22)."
    elif "ftp" in service or port == 21:
        advice = "High Risk: FTP is insecure. Migrate to SFTP or FTPS to encrypt file transfers."
    elif "http" in service or port == 80:
        advice = "Ensure HTTPS redirection is enabled. Check for exposed sensitive directories (robots.txt, .git)."
    elif "ssl" in service or port == 443:
        advice = "Verify SSL/TLS certificate validity. Disable outdated protocols like TLS 1.0/1.1."
    elif "sql" in service or port == 3306 or port == 5432:
        advice = "Ensure Database is not exposed to the public internet. Whitelist trusted IPs only."
    elif "ssh" in service or port == 22:
        advice = "Disable Root Login and Password Authentication. Use SSH Keys only."
    elif "rdp" in service or port == 3389:
        advice = "Critical: RDP should not be exposed publicly. Use a VPN to access this service."
        
    # Logic based on Risk Label
    if "cve-" in risk:
        advice = "PATCH IMMEDIATELY. Refer to the specific CVE vendor bulletin for security updates."
    elif "misconfiguration" in risk:
        advice = "Update the web server configuration (Nginx/Apache) to include missing security headers."

    return advice