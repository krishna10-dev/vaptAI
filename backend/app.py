import sqlite3
import json
import io
import os
import re
import hashlib
import threading
import time
import logging
from datetime import datetime
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.colors import HexColor
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from werkzeug.exceptions import HTTPException

# Import custom modules
from scanner import VulnerabilityScanner
from remediation import get_remediation
from ai_helper import get_ai_analysis, get_chat_response, get_ai_patch, get_attack_suggestion
from recon_helper import get_whois_info, get_dns_records, get_ssl_details, get_tech_stack, get_geo_info, get_server_health
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from scapy.all import rdpcap, IP, TCP, UDP, ICMP

app = Flask(__name__)
CORS(app)
LOGGER = logging.getLogger(__name__)

active_scans = {}

# --- BACKGROUND CLEANUP ---
def cleanup_old_scans():
    """Removes scans older than 1 hour from memory."""
    while True:
        try:
            now = time.time()
            to_delete = [
                sid for sid, data in active_scans.items() 
                if now - data.get("created_at", 0) > 3600
            ]
            for sid in to_delete:
                del active_scans[sid]
        except Exception:
            pass
        time.sleep(600)

threading.Thread(target=cleanup_old_scans, daemon=True).start()

EVIDENCE_DIR = "forensic_evidence"
if not os.path.exists(EVIDENCE_DIR):
    os.makedirs(EVIDENCE_DIR)
DB_PATH = "vapt_data.db"
DEFAULT_AES_KEY = os.getenv("VAPTAI_AES_KEY", "default_secret_key_32_chars_long!")
ALLOWED_SCAN_MODES = {"quick", "full"}

def validate_target(target):
    """Simple validation for host/IP target."""
    import re
    # Allow alphanumeric, dots, dashes, and protocol
    return bool(re.match(r'^(https?://)?[a-zA-Z0-9.-]+(/[a-zA-Z0-9._/-]*)?$', target))


def _json_body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def _scan_record_not_found(scan_id):
    return {"error": f"Scan '{scan_id}' not found"}

# --- DATABASE SETUP ---
def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS scans 
                     (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                      target TEXT, 
                      timestamp TEXT, 
                      vuln_count INTEGER, 
                      scan_data TEXT,
                      integrity_hash TEXT)''')
        conn.commit()

init_db()

# --- BACKGROUND TASK RUNNER ---
def run_async_scan(scan_id, target, mode="quick"):
    print(f"🚀 Launching Interactive Pentest: {target}")
    host = target.replace("http://", "").replace("https://", "").split("/")[0]
    
    try:
        if scan_id not in active_scans:
            return
        scanner = VulnerabilityScanner()
        active_scans[scan_id]["status"] = "running"
        active_scans[scan_id]["warnings"] = []
        if scanner.nm is None:
            active_scans[scan_id]["warnings"].append(
                "nmap not available: using fallback TCP scan on common ports."
            )
        
        # 1. Human-Friendly Health & Recon
        active_scans[scan_id]["message"] = "Checking server pulse & geolocation..."
        active_scans[scan_id]["health"] = get_server_health(target)
        active_scans[scan_id]["geo"] = get_geo_info(host)
        
        active_scans[scan_id]["message"] = "Mining WHOIS & DNS intelligence..."
        active_scans[scan_id]["recon"] = {
            "whois": get_whois_info(host),
            "dns": get_dns_records(host),
            "tech": get_tech_stack(target)
        }

        # 2. Security Checks
        active_scans[scan_id]["message"] = "Auditing SSL/TLS strength..."
        active_scans[scan_id]["ssl"] = get_ssl_details(host)

        active_scans[scan_id]["message"] = "Enumerating subdomains..."
        subdomains = scanner.enumerate_subdomains(host)
        active_scans[scan_id]["subdomains"] = subdomains

        active_scans[scan_id]["message"] = "Scanning ports & service banners..."
        network_results = scanner.scan_target(target)
        
        # 3. Deep Analysis (Mode based)
        web_results = []
        nuclei_results = []
        if mode == "full":
            active_scans[scan_id]["message"] = "Performing Deep Nuclei Audit..."
            nuclei_results = scanner.run_nuclei(target)
            web_results = scanner.check_web_headers(target)
        
        full_results = network_results + web_results + nuclei_results
        
        # 4. Finalize
        active_scans[scan_id]["message"] = "Generating AI Security Insights..."
        for item in full_results:
            item['remediation'] = get_remediation(item['service'], item['port'], item['risk_level'])
            item['ai_suggestion'] = get_attack_suggestion(item)
            
            # For Full scans, get technical patches for Critical/High risks
            if mode == "full" and any(x in str(item.get('risk_level', '')).upper() for x in ["CRITICAL", "HIGH"]):
                item['ai_patch'] = get_ai_patch(item)

        ai_analysis = get_ai_analysis(target, full_results)
        ai_report = ai_analysis.get("ai_report", "AI analysis unavailable.")
        security_score = ai_analysis.get("security_score", 0)

        scan_payload = {
            "target": target,
            "mode": mode,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "health": active_scans[scan_id]["health"],
            "geo": active_scans[scan_id]["geo"],
            "recon": active_scans[scan_id]["recon"],
            "ssl": active_scans[scan_id]["ssl"],
            "subdomains": subdomains,
            "vulnerabilities": full_results,
            "ai_report": ai_report,
            "security_score": security_score
        }
        
        data_json = json.dumps(scan_payload)
        integrity_hash = hashlib.sha256(data_json.encode()).hexdigest()

        # Save to DB
        with sqlite3.connect(DB_PATH) as conn:
            conn.cursor().execute(
                "INSERT INTO scans (target, timestamp, vuln_count, scan_data, integrity_hash) VALUES (?, ?, ?, ?, ?)",
                (target, scan_payload["timestamp"], len(full_results), data_json, integrity_hash),
            )
            conn.commit()

        active_scans[scan_id]["status"] = "completed"
        if active_scans[scan_id]["warnings"]:
            active_scans[scan_id]["message"] = "Interactive Scan Complete (with warnings)."
        else:
            active_scans[scan_id]["message"] = "Interactive Scan Complete."
        
        # Ensure all data is available in the active_scans memory for the frontend
        active_scans[scan_id]["scan_data"] = full_results
        active_scans[scan_id]["health"] = scan_payload["health"]
        active_scans[scan_id]["geo"] = scan_payload["geo"]
        active_scans[scan_id]["recon"] = scan_payload["recon"]
        active_scans[scan_id]["ssl"] = scan_payload["ssl"]
        active_scans[scan_id]["subdomains"] = scan_payload["subdomains"]
        active_scans[scan_id]["ai_report"] = ai_report
        active_scans[scan_id]["security_score"] = security_score
        active_scans[scan_id]["integrity_hash"] = integrity_hash

    except Exception as e:
        print(f"❌ Pentest Failed: {e}")
        if scan_id in active_scans:
            active_scans[scan_id]["status"] = "failed"
            active_scans[scan_id]["message"] = str(e)

# --- API ENDPOINTS ---

@app.route('/', methods=['GET'])
def index():
    return jsonify({
        "service": "VaptAI Backend",
        "status": "ok",
        "hint": "Use /api/health or /api/history to test the API."
    })

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({"status": "ok"})

@app.route('/api/scan', methods=['POST'])
def start_scan():
    data = _json_body()
    target = str(data.get('target', '')).strip()
    mode = str(data.get('mode', 'quick')).strip().lower()
    
    if not target:
        return jsonify({"error": "Target required"}), 400
    if not validate_target(target):
        return jsonify({"error": "Invalid target format. Only domains/IPs allowed."}), 400
    if mode not in ALLOWED_SCAN_MODES:
        return jsonify({"error": "mode must be one of: quick, full"}), 400

    scan_id = f"scan_{time.time_ns()}"
    active_scans[scan_id] = {
        "target": target, 
        "mode": mode, 
        "status": "pending", 
        "message": "Spinning up agent...",
        "created_at": time.time()
    }
    threading.Thread(target=run_async_scan, args=(scan_id, target, mode), daemon=True).start()
    return jsonify({"status": "started", "scan_id": scan_id})

@app.route('/api/scan_status/<scan_id>', methods=['GET'])
def get_scan_status(scan_id):
    status = active_scans.get(scan_id)
    if status is None:
        return jsonify(_scan_record_not_found(scan_id)), 404
    return jsonify(status)

@app.route('/api/history', methods=['GET'])
def get_history():
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.cursor().execute(
                "SELECT id, target, timestamp, vuln_count FROM scans ORDER BY id DESC LIMIT 10"
            ).fetchall()
        return jsonify([dict(row) for row in rows])
    except Exception:
        LOGGER.exception("Failed to fetch scan history")
        return jsonify({"error": "Failed to load scan history"}), 500

# Backward-compatible aliases if frontend base URL is configured without `/api`.
@app.route('/history', methods=['GET'])
def get_history_alias():
    return get_history()

@app.route('/api/history/<int:scan_id>', methods=['GET'])
def get_scan_details(scan_id):
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.cursor().execute(
                "SELECT * FROM scans WHERE id = ?", (scan_id,)
            ).fetchone()
        if not row:
            return jsonify({"error": "Scan not found"}), 404
        
        data = dict(row)
        # Parse the JSON scan_data
        try:
            data['full_details'] = json.loads(data['scan_data'])
        except Exception:
            data['full_details'] = {}
        
        return jsonify(data)
    except Exception:
        LOGGER.exception("Failed to fetch scan details")
        return jsonify({"error": "Failed to load scan details"}), 500

@app.route('/api/ai_analyze', methods=['POST'])
def ai_analyze():
    data = _json_body()
    target = data.get('target', '')
    scan_data = data.get('scan_data', [])
    if scan_data is None:
        scan_data = []
    if not isinstance(scan_data, list):
        return jsonify({"error": "scan_data must be a list"}), 400
    return jsonify(get_ai_analysis(target, scan_data))

@app.route('/api/ai_patch', methods=['POST'])
def ai_patch():
    data = _json_body()
    vuln = data.get('vuln', {}) or {}
    if not isinstance(vuln, dict):
        return jsonify({"error": "vuln must be an object"}), 400
    return jsonify({"patch": get_ai_patch(vuln)})

@app.route('/api/chat', methods=['POST'])
def chat():
    data = _json_body()
    message = data.get('message', '')
    scan_context = data.get('scan_context', {}) or {}
    if not isinstance(scan_context, dict):
        return jsonify({"error": "scan_context must be an object"}), 400
    return jsonify({"response": get_chat_response(message, scan_context)})

@app.route('/api/report', methods=['POST'])
def generate_pdf():
    data = _json_body()
    target = str(data.get('target') or 'unknown-target')
    scan_data = data.get('scan_data', [])
    recon = data.get('recon', {})
    ssl = data.get('ssl', {})
    health = data.get('health', {})
    geo = data.get('geo', {})
    subdomains = data.get('subdomains', [])
    ai_report = str(data.get('ai_report') or '')
    security_score = data.get('security_score')
    mode = str(data.get('mode', 'unknown')).upper()
    integrity_hash = data.get('integrity_hash')
    warnings = data.get('warnings', [])
    
    safe_target = "".join(ch for ch in target if ch.isalnum() or ch in ("-", "_", ".")) or "target"
    
    LOGGER.info(f"Generating PDF for {target}. Mode: {mode}. Data keys: {list(data.keys())}")

    try:
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        elements = []

        # Custom Styles
        title_style = ParagraphStyle('TitleStyle', parent=styles['Heading1'], fontSize=26, spaceAfter=20, textColor=HexColor("#238636"), alignment=1)
        heading_style = ParagraphStyle('HeadingStyle', parent=styles['Heading2'], fontSize=18, spaceBefore=15, spaceAfter=10, textColor=HexColor("#58a6ff"), borderPadding=5)
        sub_heading_style = ParagraphStyle('SubHeadingStyle', parent=styles['Heading3'], fontSize=14, spaceBefore=10, spaceAfter=8, textColor=HexColor("#d29922"))
        body_style = styles['BodyText']
        code_style = ParagraphStyle('CodeStyle', parent=styles['Code'], fontSize=8, textColor=colors.grey)
        
        # Helper for Horizontal Line
        def add_hr():
            line_table = Table([['']], colWidths=[450])
            line_table.setStyle(TableStyle([('LINEBELOW', (0,0), (-1,0), 1, colors.grey)]))
            elements.append(line_table)
            elements.append(Spacer(1, 10))

        # 1. Title Page
        elements.append(Spacer(1, 100))
        elements.append(Paragraph(f"VaptAI Security Assessment Report", title_style))
        elements.append(Paragraph(f"Target: {target}", ParagraphStyle('TargetStyle', parent=styles['Heading2'], alignment=1, fontSize=16)))
        elements.append(Spacer(1, 20))
        elements.append(Paragraph(f"Scan Mode: {mode} Comprehensive Audit", ParagraphStyle('ModeStyle', parent=styles['Normal'], alignment=1, fontSize=12)))
        elements.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ParagraphStyle('DateStyle', parent=styles['Normal'], alignment=1, fontSize=10)))
        elements.append(Spacer(1, 50))
        
        if integrity_hash:
            elements.append(Paragraph(f"<b>Technical Integrity Hash (SHA-256):</b>", ParagraphStyle('HashLabel', parent=styles['Normal'], alignment=1, fontSize=9)))
            elements.append(Paragraph(f"<code>{integrity_hash}</code>", ParagraphStyle('HashStyle', parent=styles['Code'], alignment=1, fontSize=8, textColor=colors.grey)))
        
        elements.append(PageBreak())

        # 2. Executive Summary
        elements.append(Paragraph("1. Executive Summary", heading_style))
        elements.append(Paragraph(f"This report details the findings of a {mode.lower()} security assessment performed on {target}. The audit encompasses infrastructure reconnaissance, vulnerability identification, and AI-driven threat modeling.", body_style))
        elements.append(Spacer(1, 15))
        
        summary_data = [
            ["Metric", "Value"],
            ["Primary IP Address", geo.get('ip', 'Unknown')],
            ["Security Posture Grade", health.get('security_grade', 'N/A')],
            ["AI-Calculated Risk Score", f"{security_score}/100" if security_score is not None else "N/A"],
            ["Average Latency", f"{health.get('latency_ms', 'N/A')} ms"],
            ["Vulnerabilities Found", len(scan_data)],
            ["Critical/High Risks", len([v for v in scan_data if any(x in str(v.get('risk_level', '')).upper() for x in ["CRITICAL", "HIGH"])])],
            ["Geographic Location", f"{geo.get('city', 'Unknown')}, {geo.get('country', 'Unknown')}"],
            ["Service Provider", geo.get('isp', 'Unknown')]
        ]
        t_summary = Table(summary_data, colWidths=[180, 270])
        t_summary.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor("#161b22")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), HexColor("#f6f8fa")),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
        ]))
        elements.append(t_summary)
        elements.append(Spacer(1, 20))

        # Warnings Section
        if warnings:
            elements.append(Paragraph("Scan Warnings & Limitations", sub_heading_style))
            for w in warnings:
                elements.append(Paragraph(f"&bull; {w}", ParagraphStyle('WarnStyle', parent=body_style, textColor=HexColor("#cf222e"))))
            elements.append(Spacer(1, 15))

        # 3. AI Intelligence Analysis
        if ai_report:
            elements.append(Paragraph("2. AI-Powered Threat Intelligence", heading_style))
            
            # Improved Markdown-to-Paragraph converter
            import html
            
            def md_to_reportlab(text):
                # 1. Escape HTML special characters
                text = html.escape(text)
                # 2. Replace Bold (**text** or __text__)
                text = re.sub(r'(\*\*|__)(.*?)\1', r'<b>\2</b>', text)
                # 3. Replace Italic (*text* or _text_)
                text = re.sub(r'(\*|_)(.*?)\1', r'<i>\2</i>', text)
                # 4. Replace Inline Code (`text`)
                text = re.sub(r'`(.*?)`', r'<font name="Courier" size="8" color="#6e7681">\1</font>', text)
                return text

            lines = ai_report.split('\n')
            for line in lines:
                line = line.strip()
                if not line:
                    elements.append(Spacer(1, 6))
                    continue
                
                if line.startswith('### '):
                    elements.append(Paragraph(md_to_reportlab(line[4:]), styles['Heading4']))
                elif line.startswith('## '):
                    elements.append(Paragraph(md_to_reportlab(line[3:]), styles['Heading3']))
                elif line.startswith('# '):
                    elements.append(Paragraph(md_to_reportlab(line[2:]), styles['Heading2']))
                elif line.startswith('- ') or line.startswith('* '):
                    elements.append(Paragraph(f"&bull; {md_to_reportlab(line[2:])}", body_style))
                elif re.match(r'^\d+\.', line): # Numbered list
                    elements.append(Paragraph(md_to_reportlab(line), body_style))
                else:
                    elements.append(Paragraph(md_to_reportlab(line), body_style))
            elements.append(Spacer(1, 20))

        # 4. Reconnaissance & Digital Footprint
        elements.append(PageBreak())
        elements.append(Paragraph("3. Reconnaissance & Digital Footprint", heading_style))
        
        # SSL Info
        if ssl and ssl.get('status') != 'UNAVAILABLE':
            elements.append(Paragraph("3.1 SSL/TLS Security Configuration", sub_heading_style))
            ssl_data = [["Property", "Details"]]
            for k, v in ssl.items():
                if k not in ['status', 'grade']:
                    ssl_data.append([str(k).replace('_', ' ').title(), str(v)])
            t_ssl = Table(ssl_data, colWidths=[150, 300])
            t_ssl.setStyle(TableStyle([('GRID', (0, 0), (-1, -1), 0.5, colors.grey), ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'), ('BACKGROUND', (0, 1), (-1, -1), HexColor("#f6f8fa"))]))
            elements.append(t_ssl)
            elements.append(Spacer(1, 15))

        # DNS Info
        if recon.get('dns'):
            elements.append(Paragraph("3.2 DNS Records Identification", sub_heading_style))
            dns_data = [["Record Type", "Values"]]
            for k, v in recon['dns'].items():
                if v:
                    dns_data.append([k, ", ".join(v) if isinstance(v, list) else str(v)])
            if len(dns_data) > 1:
                t_dns = Table(dns_data, colWidths=[100, 350])
                t_dns.setStyle(TableStyle([('GRID', (0, 0), (-1, -1), 0.5, colors.grey), ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'), ('BACKGROUND', (0, 1), (-1, -1), HexColor("#f6f8fa"))]))
                elements.append(t_dns)
                elements.append(Spacer(1, 15))

        # WHOIS Info
        if recon.get('whois') and 'error' not in recon['whois']:
            elements.append(Paragraph("3.3 WHOIS Registry Data", sub_heading_style))
            whois = recon['whois']
            whois_data = [["Field", "Value"]]
            for k in ['domain_name', 'registrar', 'creation_date', 'expiration_date', 'org']:
                val = whois.get(k)
                if val and val != "N/A":
                    whois_data.append([k.replace('_', ' ').title(), str(val)])
            if len(whois_data) > 1:
                t_whois = Table(whois_data, colWidths=[150, 300])
                t_whois.setStyle(TableStyle([('GRID', (0, 0), (-1, -1), 0.5, colors.grey), ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'), ('BACKGROUND', (0, 1), (-1, -1), HexColor("#f6f8fa"))]))
                elements.append(t_whois)
                elements.append(Spacer(1, 15))

        # Tech Stack
        if recon.get('tech') and 'error' not in recon['tech']:
            elements.append(Paragraph("3.4 Technology Stack Profiling", sub_heading_style))
            tech_data = [["Category", "Detected Technology"]]
            for k, v in recon['tech'].items():
                if v and v != "Hidden":
                    display_val = ", ".join(v) if isinstance(v, list) else str(v)
                    tech_data.append([str(k).replace('_', ' ').title(), display_val])
            if len(tech_data) > 1:
                t_tech = Table(tech_data, colWidths=[150, 300])
                t_tech.setStyle(TableStyle([('GRID', (0, 0), (-1, -1), 0.5, colors.grey), ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'), ('BACKGROUND', (0, 1), (-1, -1), HexColor("#f6f8fa"))]))
                elements.append(t_tech)
                elements.append(Spacer(1, 15))

        # Subdomains
        if subdomains:
            elements.append(Paragraph("3.5 Subdomain Enumeration", sub_heading_style))
            sub_data = [["Subdomain", "IP Address"]]
            for s in subdomains[:50]: # Show top 50
                sub_data.append([s.get('subdomain', 'N/A'), s.get('ip', 'N/A')])
            t_sub = Table(sub_data, colWidths=[300, 150])
            t_sub.setStyle(TableStyle([('GRID', (0, 0), (-1, -1), 0.5, colors.grey), ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'), ('BACKGROUND', (0, 1), (-1, -1), HexColor("#f6f8fa"))]))
            elements.append(t_sub)
            elements.append(Spacer(1, 15))

        # Security Headers
        if health.get('missing_headers'):
            elements.append(Paragraph("3.6 Security Header Audit", sub_heading_style))
            header_data = [["Missing Header", "Severity", "Impact"]]
            impact_map = {
                "Content-Security-Policy": ("High", "XSS and Injection protection."),
                "Strict-Transport-Security": ("Medium", "Enforcement of HTTPS."),
                "X-Frame-Options": ("Medium", "Clickjacking prevention."),
                "X-Content-Type-Options": ("Low", "MIME sniffing protection."),
                "Referrer-Policy": ("Low", "Information leakage.")
            }
            for mh in health['missing_headers']:
                sev, impact = impact_map.get(mh, ("Low", "General security hardening."))
                header_data.append([mh, sev, impact])
            t_head = Table(header_data, colWidths=[150, 70, 230])
            t_head.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), HexColor("#161b22")),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('BACKGROUND', (0, 1), (-1, -1), HexColor("#f6f8fa"))
            ]))
            elements.append(t_head)
            elements.append(Spacer(1, 20))

        # 5. Vulnerability Inventory
        elements.append(PageBreak())
        elements.append(Paragraph("4. Technical Vulnerability Inventory", heading_style))
        if scan_data:
            def get_risk_rank(v):
                risk = str(v.get('risk_level', 'LOW')).upper()
                if "CRITICAL" in risk: return 0
                if "HIGH" in risk: return 1
                if "MEDIUM" in risk: return 2
                return 3
            
            sorted_scan_data = sorted(scan_data, key=get_risk_rank)

            for i, v in enumerate(sorted_scan_data):
                risk = str(v.get('risk_level', 'LOW')).upper()
                risk_color = HexColor("#f85149") if any(x in risk for x in ["CRITICAL", "HIGH"]) else HexColor("#d29922") if "MEDIUM" in risk else HexColor("#238636")
                
                elements.append(Paragraph(f"Finding {i+1}: {v.get('service', 'N/A').upper()} Analysis", sub_heading_style))
                
                cve_list = v.get('cves', [])
                cve_str = ", ".join(cve_list) if isinstance(cve_list, list) and cve_list else "None"
                
                detail_data = [
                    ["Attribute", "Information"],
                    ["Risk Level", risk],
                    ["Service/Port", f"{v.get('service')} / {v.get('port')} ({v.get('protocol', 'tcp')})"],
                    ["Detected Product", v.get('product', 'N/A')],
                    ["Version Info", v.get('version', 'N/A')],
                    ["Associated CVEs", cve_str]
                ]
                t_det = Table(detail_data, colWidths=[120, 330])
                t_det.setStyle(TableStyle([
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ('TEXTCOLOR', (1, 1), (1, 1), risk_color),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('BACKGROUND', (0, 0), (0, -1), HexColor("#f6f8fa"))
                ]))
                elements.append(t_det)
                elements.append(Spacer(1, 10))
                
                elements.append(Paragraph("<b>Remediation Strategy:</b>", body_style))
                elements.append(Paragraph(str(v.get('remediation', 'N/A')), body_style))
                
                if v.get('ai_suggestion'):
                    elements.append(Spacer(1, 5))
                    elements.append(Paragraph("<b>AI Security Insight:</b>", body_style))
                    elements.append(Paragraph(f"<i>{v.get('ai_suggestion')}</i>", body_style))
                
                if v.get('ai_patch'):
                    elements.append(Spacer(1, 5))
                    elements.append(Paragraph("<b>AI Remediation Patch:</b>", body_style))
                    elements.append(Paragraph(str(v.get('ai_patch')), ParagraphStyle('PatchStyle', parent=body_style, leftIndent=10, textColor=HexColor("#1f6feb"))))
                
                elements.append(Spacer(1, 10))
                add_hr()
        else:
            elements.append(Paragraph("No significant vulnerabilities were identified during this assessment cycle.", body_style))

        # Footer
        elements.append(Spacer(1, 50))
        elements.append(Paragraph("--- End of Security Report ---", ParagraphStyle('Footer', parent=styles['Normal'], alignment=1, textColor=colors.grey)))
        elements.append(Paragraph("Generated by VaptAI Security Engine. This report is for informational purposes only.", ParagraphStyle('Disclaimer', parent=styles['Normal'], alignment=1, fontSize=8, textColor=colors.grey)))

        # Build PDF
        doc.build(elements)
        buffer.seek(0)
        return send_file(
            buffer,
            as_attachment=True,
            download_name=f"VaptAI_Full_Report_{safe_target}.pdf",
            mimetype='application/pdf',
        )
    except Exception:
        LOGGER.exception("Failed to generate PDF report")
        return jsonify({"error": "Failed to generate report"}), 500

@app.route('/api/calculate_hash', methods=['POST'])
def calculate_hash():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    
    try:
        file_content = file.read()
        md5_hash = hashlib.md5(file_content).hexdigest()
        sha1_hash = hashlib.sha1(file_content).hexdigest()
        sha256_hash = hashlib.sha256(file_content).hexdigest()
    except Exception:
        LOGGER.exception("Failed to calculate hashes")
        return jsonify({"error": "Hash calculation failed"}), 500
    
    return jsonify({
        "filename": file.filename,
        "md5": md5_hash,
        "sha1": sha1_hash,
        "sha256": sha256_hash,
        "size": len(file_content)
    })

@app.route('/api/encrypt', methods=['POST'])
def aes_encrypt():
    data = _json_body()
    text = str(data.get('text', ''))
    key = str(data.get('key') or DEFAULT_AES_KEY)
    if not text:
        return jsonify({"error": "Text required"}), 400

    try:
        key_bytes = key.encode().ljust(32)[:32]
        iv = os.urandom(16)

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(text.encode()) + padder.finalize()

        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ct = encryptor.update(padded_data) + encryptor.finalize()

        return jsonify({
            "ciphertext": base64.b64encode(iv + ct).decode('utf-8')
        })
    except Exception:
        LOGGER.exception("AES encryption failed")
        return jsonify({"error": "Encryption failed"}), 500

@app.route('/api/decrypt', methods=['POST'])
def aes_decrypt():
    data = _json_body()
    ciphertext = str(data.get('ciphertext', ''))
    key = str(data.get('key') or DEFAULT_AES_KEY)
    if not ciphertext:
        return jsonify({"error": "Ciphertext required"}), 400
    
    try:
        raw_data = base64.b64decode(ciphertext, validate=True)
        if len(raw_data) < 17:
            return jsonify({"error": "Invalid ciphertext format"}), 400
        iv, ct = raw_data[:16], raw_data[16:]
        key_bytes = key.encode().ljust(32)[:32]
        
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ct) + decryptor.finalize()
        
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        return jsonify({"text": data.decode('utf-8')})
    except Exception:
        return jsonify({"error": "Decryption failed. Invalid key or data."}), 400

@app.route('/api/base64', methods=['POST'])
def base64_tool():
    data = _json_body()
    text, action = str(data.get('text', '')), str(data.get('action', 'encode')).lower()
    if not text:
        return jsonify({"error": "Text required"}), 400
    if action not in {"encode", "decode"}:
        return jsonify({"error": "action must be 'encode' or 'decode'"}), 400
    
    try:
        if action == 'encode':
            res = base64.b64encode(text.encode()).decode()
        else:
            res = base64.b64decode(text, validate=True).decode()
        return jsonify({"result": res})
    except Exception:
        return jsonify({"error": "Base64 operation failed"}), 400

@app.route('/api/analyze_pcap', methods=['POST'])
def analyze_pcap():
    if 'file' not in request.files:
        return jsonify({"error": "No file"}), 400
    file = request.files['file']
    if not file.filename:
        return jsonify({"error": "No selected file"}), 400
    
    import uuid
    pcap_filename = f"temp_{uuid.uuid4().hex}.pcap"
    pcap_path = os.path.join(EVIDENCE_DIR, pcap_filename)
    try:
        file.save(pcap_path)
    except Exception:
        LOGGER.exception("Failed to save uploaded PCAP")
        return jsonify({"error": "Failed to save uploaded file"}), 500
    
    try:
        packets = rdpcap(pcap_path)
        summary = []
        for i, pkt in enumerate(packets[:100]): # Limit to 100 packets for performance
            if IP in pkt:
                proto = "Other"
                if TCP in pkt: proto = "TCP"
                elif UDP in pkt: proto = "UDP"
                elif ICMP in pkt: proto = "ICMP"
                
                summary.append({
                    "id": i,
                    "src": pkt[IP].src,
                    "dst": pkt[IP].dst,
                    "proto": proto,
                    "len": len(pkt),
                    "info": pkt.summary()
                })
        
        return jsonify({"packets": summary, "count": len(packets)})
    except Exception as e:
        return jsonify({"error": f"Failed to parse PCAP: {str(e)}"}), 500
    finally:
        if os.path.exists(pcap_path):
            try:
                os.remove(pcap_path)
            except OSError:
                LOGGER.warning("Could not remove temp pcap file: %s", pcap_path)


@app.errorhandler(Exception)
def handle_uncaught_exception(err):
    if isinstance(err, HTTPException):
        return jsonify({"error": err.description}), err.code
    LOGGER.exception("Unhandled backend exception")
    return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    port = int(os.getenv("PORT", "5000"))
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", debug=debug, port=port)
