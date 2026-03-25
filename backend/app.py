import sqlite3
import json
import io
import os
import hashlib
import threading
import time
from datetime import datetime
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

# Import custom modules
from scanner import VulnerabilityScanner
from remediation import get_remediation
from ai_helper import get_ai_analysis, get_chat_response

app = Flask(__name__)
CORS(app)

# Global dictionary to track active scans
# Format: { "scan_id": { "status": "running/completed/failed", "data": ..., "progress": 0 } }
active_scans = {}

# Ensure evidence directory exists for Forensics
EVIDENCE_DIR = "forensic_evidence"
if not os.path.exists(EVIDENCE_DIR):
    os.makedirs(EVIDENCE_DIR)

# --- DATABASE SETUP ---
def init_db():
    conn = sqlite3.connect('vapt_data.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scans 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                  target TEXT, 
                  timestamp TEXT, 
                  vuln_count INTEGER, 
                  scan_data TEXT,
                  evidence_file TEXT,
                  integrity_hash TEXT)''')
    conn.commit()
    conn.close()

init_db()

def calculate_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# --- BACKGROUND TASK RUNNER ---
def run_async_scan(scan_id, target):
    print(f"🧵 Background Thread Started for: {target}")
    scanner = VulnerabilityScanner()
    
    try:
        active_scans[scan_id]["status"] = "running"
        active_scans[scan_id]["message"] = "Enumerating subdomains..."
        
        # 0. Subdomain Enumeration
        domain = target.replace("http://", "").replace("https://", "").split("/")[0]
        subdomains = scanner.enumerate_subdomains(domain)
        active_scans[scan_id]["subdomains"] = subdomains

        active_scans[scan_id]["message"] = "Enumerating ports & services..."

        # 1. Perform Network & Web Scan
        network_results = scanner.scan_target(target)
        active_scans[scan_id]["message"] = "Checking web security headers..."
        web_results = scanner.check_web_headers(target)
        
        # 1.5 Perform Nuclei Deep Scan
        active_scans[scan_id]["message"] = "Starting Deep Nuclei Vulnerability Scan..."
        nuclei_results = scanner.run_nuclei(target)
        
        full_results = network_results + web_results + nuclei_results
        
        # 2. Add Remediation Advice
        active_scans[scan_id]["message"] = "Generating remediation advice..."
        for item in full_results:
            if "remediation" not in item:
                item['remediation'] = get_remediation(item['service'], item['port'], item['risk_level'])

        # 3. FORENSIC STEP: Save Raw Evidence
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{EVIDENCE_DIR}/evidence_{target}_{timestamp}.json"
        
        # Include subdomains in the saved evidence
        evidence_payload = {
            "target": target,
            "timestamp": timestamp,
            "subdomains": subdomains,
            "vulnerabilities": full_results
        }
        
        with open(filename, 'w') as f:
            json.dump(evidence_payload, f, indent=4)
            
        file_hash = calculate_hash(filename)

        # 4. Save to Database
        conn = sqlite3.connect('vapt_data.db')
        c = conn.cursor()
        vuln_count = len(full_results)
        
        # Note: We store the full JSON payload including subdomains in scan_data
        c.execute("""INSERT INTO scans 
                     (target, timestamp, vuln_count, scan_data, evidence_file, integrity_hash) 
                     VALUES (?, ?, ?, ?, ?, ?)""",
                  (target, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), vuln_count, json.dumps(evidence_payload), filename, file_hash))
        
        conn.commit()
        conn.close()

        # Finalize Scan Entry
        active_scans[scan_id]["status"] = "completed"
        active_scans[scan_id]["message"] = "Scan Finished Successfully"
        active_scans[scan_id]["scan_data"] = full_results
        active_scans[scan_id]["subdomains"] = subdomains
        active_scans[scan_id]["integrity_hash"] = file_hash
        print(f"✅ Background Scan Completed for: {target}")

    except Exception as e:
        print(f"❌ Background Scan Error: {e}")
        active_scans[scan_id]["status"] = "failed"
        active_scans[scan_id]["message"] = str(e)

# --- ROUTE 1: INITIATE SCAN (ASYNC) ---
@app.route('/api/scan', methods=['POST'])
def start_scan():
    data = request.json
    target = data.get('target')

    if not target:
        return jsonify({"error": "Target is required"}), 400

    scan_id = f"scan_{int(time.time())}"
    active_scans[scan_id] = {
        "target": target,
        "status": "pending",
        "message": "Initializing...",
        "timestamp": datetime.now().strftime("%H:%M:%S")
    }

    # Start thread
    thread = threading.Thread(target=run_async_scan, args=(scan_id, target))
    thread.start()

    return jsonify({
        "status": "started",
        "scan_id": scan_id,
        "target": target
    })

# --- ROUTE 2: CHECK STATUS ---
@app.route('/api/scan_status/<scan_id>', methods=['GET'])
def get_scan_status(scan_id):
    status_info = active_scans.get(scan_id)
    if not status_info:
        return jsonify({"error": "Scan ID not found"}), 404
    return jsonify(status_info)

# --- ROUTE 3: FETCH HISTORY ---
@app.route('/api/history', methods=['GET'])
def get_history():
    try:
        conn = sqlite3.connect('vapt_data.db')
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT id, target, timestamp, vuln_count, integrity_hash FROM scans ORDER BY id DESC LIMIT 10")
        rows = c.fetchall()
        history = [dict(row) for row in rows]
        conn.close()
        return jsonify(history)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- ROUTE 3: AI ANALYSIS ---
@app.route('/api/ai_analyze', methods=['POST'])
def ai_analyze():
    data = request.json
    target = data.get('target')
    scan_data = data.get('scan_data')
    
    if not scan_data:
        return jsonify({"error": "No scan data provided"}), 400
        
    print(f"✨ Generating AI Report for {target}...")
    ai_data = get_ai_analysis(target, scan_data)
    
    return jsonify({
        "status": "success",
        "ai_report": ai_data.get("ai_report"),
        "security_score": ai_data.get("security_score")
    })

# --- ROUTE 4.5: SECURE CHAT ---
@app.route('/api/chat', methods=['POST'])
def secure_chat():
    data = request.json
    message = data.get('message')
    scan_context = data.get('scan_context')
    
    if not message:
        return jsonify({"error": "Message is required"}), 400
        
    ai_response = get_chat_response(message, scan_context)
    
    return jsonify({
        "status": "success",
        "response": ai_response
    })

# --- ROUTE 4: DOWNLOAD EVIDENCE (Placeholder for future) ---
@app.route('/api/evidence_download', methods=['POST'])
def download_evidence():
    return jsonify({"message": "Forensic files are stored securely on the server in 'forensic_evidence/' folder."})

# --- ROUTE 5: PDF REPORTING ---
@app.route('/api/report', methods=['POST'])
def generate_report():
    data = request.json
    target = data.get('target')
    scan_results = data.get('scan_data', [])
    ai_report = data.get('ai_report')
    subdomains = data.get('subdomains', [])

    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    
    # --- PAGE 1: TITLE & AI SUMMARY ---
    c.setFont("Helvetica-Bold", 22)
    c.setFillColor("#238636")
    c.drawString(50, 750, "VaptAI Professional Security Report")
    
    c.setFont("Helvetica", 12)
    c.setFillColor("black")
    c.drawString(50, 730, f"Target: {target}")
    c.drawString(50, 715, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    c.line(50, 705, 550, 705)

    y = 680
    
    # 1. AI Security Insights Section
    if ai_report:
        c.setFont("Helvetica-Bold", 16)
        c.drawString(50, y, "🧠 AI Security Insights")
        y -= 25
        
        c.setFont("Helvetica", 10)
        text_object = c.beginText(50, y)
        text_object.setTextOrigin(50, y)
        text_object.setFont("Helvetica", 10)
        
        # Split AI report into lines to handle text wrapping
        lines = ai_report.split('\n')
        for line in lines:
            if y < 100:
                c.drawText(text_object)
                c.showPage()
                y = 750
                text_object = c.beginText(50, y)
                text_object.setFont("Helvetica", 10)
            
            # Simple word wrap logic
            if len(line) > 90:
                words = line.split(' ')
                current_line = ""
                for word in words:
                    if len(current_line + word) < 90:
                        current_line += word + " "
                    else:
                        text_object.textLine(current_line)
                        y -= 12
                        current_line = word + " "
                text_object.textLine(current_line)
                y -= 12
            else:
                text_object.textLine(line)
                y -= 12
        
        c.drawText(text_object)
        y -= 20

    # 2. Subdomains Section
    if subdomains:
        if y < 150:
            c.showPage()
            y = 750
            
        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, y, "🌐 Discovered Subdomains")
        y -= 20
        c.setFont("Helvetica", 9)
        for sub in subdomains:
            c.drawString(60, y, f"• {sub['subdomain']} ({sub['ip']})")
            y -= 15
            if y < 80:
                c.showPage()
                y = 750
        y -= 20

    # --- NEW PAGE: TECHNICAL SCAN RESULTS ---
    c.showPage()
    y = 750
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, y, "📊 Technical Scan Results")
    y -= 30

    for item in scan_results:
        # Page Break Logic
        if y < 150:
            c.showPage()
            y = 750
            
        # Port Info
        c.setFont("Helvetica-Bold", 11)
        c.drawString(50, y, f"Port: {item['port']} ({item['protocol']}) - {item['service']}")
        
        # Risk Label
        risk_color = "#da3633" if "CRITICAL" in item['risk_level'] or "High" in item['risk_level'] else "black"
        c.setFillColor(risk_color)
        c.drawString(400, y, f"[{item['risk_level']}]")
        c.setFillColor("black") 
        
        y -= 15
        
        # Service Version
        c.setFont("Helvetica", 10)
        c.drawString(60, y, f"Product: {item.get('product', 'Unknown')} | Version: {item.get('version', 'Unknown')}")
        y -= 15
        
        # CVEs
        if item.get('cves'):
            c.setFont("Courier", 9)
            c.setFillColor("#da3633")
            c.drawString(60, y, f"Detected CVEs: {', '.join(item['cves'][:3])}")
            c.setFillColor("black")
            y -= 15

        # Remediation Advice
        c.setFont("Helvetica-Oblique", 9)
        c.setFillColor("#444444")
        rem_text = f"Fix: {item.get('remediation', 'N/A')}"
        if len(rem_text) > 90:
            rem_text = rem_text[:90] + "..."
            
        c.drawString(60, y, rem_text)
        
        y -= 25 
        c.setStrokeColor("#eeeeee")
        c.line(50, y+10, 550, y+10)

    c.save()
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name=f"VAPT_Report_{target}.pdf", mimetype='application/pdf')

if __name__ == '__main__':
    app.run(debug=True, port=5000)