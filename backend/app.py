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
from ai_helper import get_ai_analysis, get_chat_response, get_ai_patch, get_attack_suggestion
from recon_helper import get_whois_info, get_dns_records, get_ssl_details, get_tech_stack, get_geo_info, get_server_health
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, conf

app = Flask(__name__)
CORS(app)

active_scans = {}
active_pcap = {}

EVIDENCE_DIR = "forensic_evidence"
if not os.path.exists(EVIDENCE_DIR): os.makedirs(EVIDENCE_DIR)

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
                  integrity_hash TEXT)''')
    conn.commit()
    conn.close()

init_db()

# --- BACKGROUND TASK RUNNER ---
def run_async_scan(scan_id, target, mode="quick"):
    print(f"🚀 Launching Interactive Pentest: {target}")
    scanner = VulnerabilityScanner()
    host = target.replace("http://", "").replace("https://", "").split("/")[0]
    
    try:
        active_scans[scan_id]["status"] = "running"
        
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
        for item in full_results:
            item['remediation'] = get_remediation(item['service'], item['port'], item['risk_level'])
            item['ai_suggestion'] = get_attack_suggestion(item)

        scan_payload = {
            "target": target,
            "mode": mode,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "health": active_scans[scan_id]["health"],
            "geo": active_scans[scan_id]["geo"],
            "recon": active_scans[scan_id]["recon"],
            "ssl": active_scans[scan_id]["ssl"],
            "subdomains": subdomains,
            "vulnerabilities": full_results
        }
        
        data_json = json.dumps(scan_payload)
        integrity_hash = hashlib.sha256(data_json.encode()).hexdigest()

        # Save to DB
        conn = sqlite3.connect('vapt_data.db')
        conn.cursor().execute("INSERT INTO scans (target, timestamp, vuln_count, scan_data, integrity_hash) VALUES (?, ?, ?, ?, ?)",
                  (target, scan_payload["timestamp"], len(full_results), data_json, integrity_hash))
        conn.commit()
        conn.close()

        active_scans[scan_id]["status"] = "completed"
        active_scans[scan_id]["message"] = "Interactive Scan Complete."
        active_scans[scan_id]["scan_data"] = full_results
        active_scans[scan_id]["integrity_hash"] = integrity_hash

    except Exception as e:
        print(f"❌ Pentest Failed: {e}")
        active_scans[scan_id]["status"] = "failed"
        active_scans[scan_id]["message"] = str(e)

# --- API ENDPOINTS ---

@app.route('/api/scan', methods=['POST'])
def start_scan():
    data = request.json
    target, mode = data.get('target'), data.get('mode', 'quick')
    if not target: return jsonify({"error": "Target required"}), 400
    
    scan_id = f"scan_{int(time.time())}"
    active_scans[scan_id] = {"target": target, "mode": mode, "status": "pending", "message": "Spinning up agent..."}
    threading.Thread(target=run_async_scan, args=(scan_id, target, mode)).start()
    return jsonify({"status": "started", "scan_id": scan_id})

@app.route('/api/scan_status/<scan_id>', methods=['GET'])
def get_scan_status(scan_id):
    return jsonify(active_scans.get(scan_id, {"error": "Not found"}))

@app.route('/api/history', methods=['GET'])
def get_history():
    conn = sqlite3.connect('vapt_data.db'); conn.row_factory = sqlite3.Row
    rows = conn.cursor().execute("SELECT id, target, timestamp, vuln_count FROM scans ORDER BY id DESC LIMIT 10").fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows])

@app.route('/api/ai_analyze', methods=['POST'])
def ai_analyze():
    data = request.json
    return jsonify(get_ai_analysis(data.get('target'), data.get('scan_data', [])))

@app.route('/api/ai_patch', methods=['POST'])
def ai_patch():
    data = request.json
    return jsonify({"patch": get_ai_patch(data.get('vuln', {}))})

@app.route('/api/chat', methods=['POST'])
def chat():
    data = request.json
    return jsonify({"response": get_chat_response(data.get('message'), data.get('scan_context', {}))})

@app.route('/api/report', methods=['POST'])
def generate_pdf():
    data = request.json
    target, scan_results, ai_report = data.get('target'), data.get('scan_data', []), data.get('ai_report', '')
    
    buffer = io.BytesIO(); c = canvas.Canvas(buffer, pagesize=letter)
    c.setFont("Helvetica-Bold", 20); c.setFillColorRGB(0.1, 0.5, 0.2)
    c.drawString(50, 750, f"Interactive Security Audit: {target}")
    
    c.setFont("Helvetica", 10); c.setFillColorRGB(0,0,0)
    c.drawString(50, 730, f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    c.line(50, 720, 550, 720)
    
    y = 700
    if ai_report:
        c.setFont("Helvetica-Bold", 14); c.drawString(50, y, "AI Intelligence Summary"); y -= 20
        c.setFont("Helvetica", 10)
        for line in ai_report.split('\n')[:15]: 
            c.drawString(50, y, line[:95]); y -= 12
    
    c.save(); buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name=f"VaptAI_{target}.pdf", mimetype='application/pdf')

@app.route('/api/calculate_hash', methods=['POST'])
def calculate_hash():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    
    file_content = file.read()
    md5_hash = hashlib.md5(file_content).hexdigest()
    sha1_hash = hashlib.sha1(file_content).hexdigest()
    sha256_hash = hashlib.sha256(file_content).hexdigest()
    
    return jsonify({
        "filename": file.filename,
        "md5": md5_hash,
        "sha1": sha1_hash,
        "sha256": sha256_hash,
        "size": len(file_content)
    })

@app.route('/api/encrypt', methods=['POST'])
def aes_encrypt():
    data = request.json
    text, key = data.get('text', ''), data.get('key', 'default_secret_key_32_chars_long!')
    if not text: return jsonify({"error": "Text required"}), 400
    
    # Ensure key is 32 bytes for AES-256
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

@app.route('/api/decrypt', methods=['POST'])
def aes_decrypt():
    data = request.json
    ciphertext, key = data.get('ciphertext', ''), data.get('key', 'default_secret_key_32_chars_long!')
    if not ciphertext: return jsonify({"error": "Ciphertext required"}), 400
    
    try:
        raw_data = base64.b64decode(ciphertext)
        iv, ct = raw_data[:16], raw_data[16:]
        key_bytes = key.encode().ljust(32)[:32]
        
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ct) + decryptor.finalize()
        
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        return jsonify({"text": data.decode('utf-8')})
    except Exception as e:
        return jsonify({"error": "Decryption failed. Invalid key or data."}), 400

@app.route('/api/base64', methods=['POST'])
def base64_tool():
    data = request.json
    text, action = data.get('text', ''), data.get('action', 'encode')
    if not text: return jsonify({"error": "Text required"}), 400
    
    try:
        if action == 'encode':
            res = base64.b64encode(text.encode()).decode()
        else:
            res = base64.b64decode(text).decode()
        return jsonify({"result": res})
    except:
        return jsonify({"error": "Base64 operation failed"}), 400

@app.route('/api/analyze_pcap', methods=['POST'])
def analyze_pcap():
    if 'file' not in request.files: return jsonify({"error": "No file"}), 400
    file = request.files['file']
    
    pcap_path = os.path.join(EVIDENCE_DIR, f"temp_{int(time.time())}.pcap")
    file.save(pcap_path)
    
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
        
        os.remove(pcap_path)
        return jsonify({"packets": summary, "count": len(packets)})
    except Exception as e:
        if os.path.exists(pcap_path): os.remove(pcap_path)
        return jsonify({"error": f"Failed to parse PCAP: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
