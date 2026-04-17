import { useState, useEffect, useRef, useCallback } from "react";
import axios from "axios";
import {
  ShieldAlert, Search, Activity, Lock, History, FileText, Hash, Send,
  Globe, ShieldCheck, Zap, Database, MapPin, AlertTriangle, X,
  Mail, Calendar, Shield
} from "lucide-react";
import ReactFlow, { Background, Controls, Handle, Position } from "reactflow";
import "reactflow/dist/style.css";
import "./App.css";

const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:5000/api";

const CustomNode = ({ data }) => (
  <div className="custom-topology-node" style={{
    padding: "12px", borderRadius: "10px",
    background: data.color || "#161b22",
    border: `1px solid ${data.borderColor || "#30363d"}`,
    color: "#fff", fontSize: "0.7rem", minWidth: "140px", textAlign: "center",
    boxShadow: "0 8px 20px rgba(0,0,0,0.4)"
  }}>
    <Handle type="target" position={Position.Top} style={{ visibility: "hidden" }} />
    <div style={{ fontWeight: "800", marginBottom: "4px" }}>{data.label}</div>
    <div style={{ opacity: 0.6, fontSize: "0.6rem" }}>{data.subtext}</div>
    <Handle type="source" position={Position.Bottom} style={{ visibility: "hidden" }} />
  </div>
);

const nodeTypes = { custom: CustomNode };

function App() {
  const [target, setTarget] = useState("");
  const [scanMode, setScanMode] = useState("quick");
  const [loading, setLoading] = useState(false);
  const [scanData, setScanData] = useState(null);
  const [reconData, setReconData] = useState(null);
  const [sslData, setSslData] = useState(null);
  const [healthData, setHealthData] = useState(null);
  const [geoData, setGeoData] = useState(null);
  const [subdomains, setSubdomains] = useState([]);
  const [history, setHistory] = useState([]);
  const [error, setError] = useState(null);
  const [aiReport, setAiReport] = useState(null);
  const [securityScore, setSecurityScore] = useState(null);
  const [integrityHash, setIntegrityHash] = useState(null);
  const [warnings, setWarnings] = useState([]);
  const [aiLoading, setAiLoading] = useState(false);
  const [chatOpen, setChatOpen] = useState(false);
  const [chatInput, setChatInput] = useState("");
  const [chatMessages, setChatMessages] = useState([
    { role: "assistant", content: "Command Center Ready. Specify target for reconnaissance." }
  ]);
  const [scanId, setScanId] = useState(null);
  const [scanStatus, setScanStatus] = useState("");
  const [activeTab, setActiveTab] = useState("vulnerabilities");
  const [selectedNodeInfo, setSelectedNodeInfo] = useState(null);
  const [fileHashData, setFileHashData] = useState(null);
  const [fileLoading, setFileLoading] = useState(false);

  const [cryptoSubTab, setCryptoSubTab] = useState("integrity");
  const [aesInput, setAesInput] = useState("");
  const [aesKey, setAesKey] = useState("");
  const [aesResult, setAesResult] = useState("");
  const [pcapData, setPcapData] = useState(null);
  const [pcapLoading, setPcapLoading] = useState(false);
  const [reportLoading, setReportLoading] = useState(false);

  const chatEndRef = useRef(null);

  const getApiError = (err, fallback) => err?.response?.data?.error || err?.message || fallback;

  const fetchHistory = useCallback(async () => {
    try {
      const res = await axios.get(`${API_BASE}/history`);
      setHistory(Array.isArray(res.data) ? res.data : []);
    } catch (err) {
      setHistory([]);
      setError(getApiError(err, "Failed to load history"));
    }
  }, []);

  useEffect(() => {
    fetchHistory();
  }, [fetchHistory]);

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [chatMessages]);

  const handleFileHash = async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    setFileLoading(true);
    setError(null);
    const formData = new FormData();
    formData.append("file", file);

    try {
      const res = await axios.post(`${API_BASE}/calculate_hash`, formData, {
        headers: { "Content-Type": "multipart/form-data" }
      });
      setFileHashData(res.data);
    } catch (err) {
      setError(`Hash calculation failed: ${getApiError(err, "Unknown error")}`);
    } finally {
      setFileLoading(false);
    }
  };

  const handleAes = async (action) => {
    if (!aesInput) return;
    setError(null);
    const endpoint = action === "encrypt" ? "encrypt" : "decrypt";
    const payload = action === "encrypt" ? { text: aesInput, key: aesKey } : { ciphertext: aesInput, key: aesKey };

    try {
      const res = await axios.post(`${API_BASE}/${endpoint}`, payload);
      setAesResult(res.data.ciphertext || res.data.text || "");
    } catch (err) {
      setError(getApiError(err, "AES operation failed"));
    }
  };

  const handleBase64 = async (action) => {
    if (!aesInput) return;
    setError(null);
    try {
      const res = await axios.post(`${API_BASE}/base64`, { text: aesInput, action });
      setAesResult(res.data.result || "");
    } catch (err) {
      setError(getApiError(err, "Base64 operation failed"));
    }
  };

  const handlePcapUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    setPcapLoading(true);
    setError(null);
    const formData = new FormData();
    formData.append("file", file);
    try {
      const res = await axios.post(`${API_BASE}/analyze_pcap`, formData, {
        headers: { "Content-Type": "multipart/form-data" }
      });
      setPcapData(res.data || null);
    } catch (err) {
      setError(getApiError(err, "PCAP analysis failed"));
    } finally {
      setPcapLoading(false);
    }
  };

  useEffect(() => {
    let interval;
    if (scanId && loading) {
      interval = setInterval(() => {
        axios.get(`${API_BASE}/scan_status/${scanId}`).then((res) => {
          setScanStatus(res.data.message);
          if (res.data.status === "completed") {
            setScanData(res.data.scan_data || []);
            setReconData(res.data.recon || null);
            setSslData(res.data.ssl || null);
            setHealthData(res.data.health || null);
            setGeoData(res.data.geo || null);
            setSubdomains(res.data.subdomains || []);
            setAiReport(res.data.ai_report || null);
            setSecurityScore(res.data.security_score || null);
            setIntegrityHash(res.data.integrity_hash || null);
            setWarnings(res.data.warnings || []);
            setLoading(false);
            setScanId(null);
            fetchHistory();
          } else if (res.data.status === "failed") {
            setError(res.data.message || "Scan failed");
            setLoading(false);
            setScanId(null);
          }
        }).catch((err) => {
          clearInterval(interval);
          setLoading(false);
          setScanId(null);
          setError(getApiError(err, "Failed to fetch scan status"));
        });
      }, 2000);
    }
    return () => clearInterval(interval);
  }, [scanId, loading, fetchHistory]);

  const handleScan = async (targetOverride = null) => {
    const scanTarget = String(targetOverride ?? target).trim();
    if (!scanTarget) return;

    setTarget(scanTarget);
    setLoading(true);
    setScanData(null);
    setReconData(null);
    setAiReport(null);
    setError(null);

    try {
      const res = await axios.post(`${API_BASE}/scan`, { target: scanTarget, mode: scanMode });
      setScanId(res.data.scan_id);
    } catch (err) {
      setLoading(false);
      setError(getApiError(err, "Failed to start scan"));
    }
  };

  const handleHistoryClick = async (historyId) => {
    setLoading(true);
    setError(null);
    setAiReport(null);
    setSecurityScore(null);
    setIntegrityHash(null);
    setWarnings([]);
    try {
      const res = await axios.get(`${API_BASE}/history/${historyId}`);
      const details = res.data.full_details;
      if (details) {
        setTarget(details.target || "");
        setScanData(details.vulnerabilities || details.scan_data || []);
        setReconData(details.recon || null);
        setSslData(details.ssl || null);
        setHealthData(details.health || null);
        setGeoData(details.geo || null);
        setSubdomains(details.subdomains || []);
        setAiReport(details.ai_report || null);
        setSecurityScore(details.security_score || null);
        setIntegrityHash(res.data.integrity_hash || details.integrity_hash || null);
        setWarnings(details.warnings || []);
        setActiveTab("vulnerabilities");
      }
    } catch (err) {
      setError(getApiError(err, "Failed to load scan details"));
    } finally {
      setLoading(false);
    }
  };

  const handleSendMessage = async () => {
    if (!chatInput.trim()) return;

    setError(null);
    const userMsg = { role: "user", content: chatInput };
    setChatMessages((prev) => [...prev, userMsg]);
    const currentInput = chatInput;
    setChatInput("");

    try {
      const res = await axios.post(`${API_BASE}/chat`, {
        message: currentInput,
        scan_context: { target, results: scanData }
      });
      setChatMessages((prev) => [...prev, { role: "assistant", content: res.data.response || "No response" }]);
    } catch (err) {
      const msg = getApiError(err, "Chat request failed");
      setError(msg);
      setChatMessages((prev) => [...prev, { role: "assistant", content: `Error: ${msg}` }]);
    }
  };

  const handleAiAnalyze = async () => {
    if (!scanData) return;

    setAiLoading(true);
    setError(null);
    try {
      const res = await axios.post(`${API_BASE}/ai_analyze`, { target, scan_data: scanData });
      setAiReport(res.data.ai_report || "No AI report generated.");
      setSecurityScore(res.data.security_score || null);
    } catch (err) {
      setError(getApiError(err, "AI analysis failed"));
    } finally {
      setAiLoading(false);
    }
  };

  const handleDownloadReport = async () => {
    if (!scanData) return;
    setReportLoading(true);
    try {
      let currentAiReport = aiReport;
      let score = securityScore;
      if (!currentAiReport) {
        const aiRes = await axios.post(`${API_BASE}/ai_analyze`, { target, scan_data: scanData });
        currentAiReport = aiRes.data.ai_report || "AI analysis failed to generate.";
        score = aiRes.data.security_score;
        setAiReport(currentAiReport);
        setSecurityScore(score);
      }

      const response = await axios.post(`${API_BASE}/report`, {
        target,
        mode: scanMode,
        scan_data: scanData,
        recon: reconData,
        ssl: sslData,
        health: healthData,
        geo: geoData,
        subdomains: subdomains,
        ai_report: currentAiReport,
        security_score: score,
        integrity_hash: integrityHash,
        warnings: warnings
      }, { responseType: 'blob' });

      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `VaptAI_Full_Report_${target.replace(/[^a-z0-9]/gi, '_')}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.remove();
    } catch (err) {
      setError(getApiError(err, "Failed to download report"));
    } finally {
      setReportLoading(false);
    }
  };

  const { nodes, edges } = (() => {
    if (!scanData) return { nodes: [], edges: [] };
    const baseNodes = [{ id: "t", type: "custom", data: { label: `🎯 ${target.toUpperCase()}`, subtext: "Primary Target", color: "#238636", borderColor: "#2ea043" }, position: { x: 400, y: 250 } }];
    const baseEdges = [];
    scanData.forEach((v, i) => {
      const riskLevel = String(v.risk_level || "");
      const isCrit = riskLevel.includes("CRITICAL");
      const nid = `v-${i}`;
      baseNodes.push({
        id: nid,
        type: "custom",
        data: {
          label: String(v.service || "unknown").toUpperCase(),
          subtext: `Port ${v.port}`,
          color: isCrit ? "#da3633" : "#161b22",
          borderColor: isCrit ? "#f85149" : "#30363d",
          fullData: v
        },
        position: { x: 100 + (i * 180), y: isCrit ? 80 : 420 }
      });
      baseEdges.push({ id: `e-${i}`, source: "t", target: nid, animated: isCrit, style: { stroke: isCrit ? "#f85149" : "#30363d", strokeWidth: 2 } });
    });
    return { nodes: baseNodes, edges: baseEdges };
  })();

  return (
    <div className="dashboard-container">
      <nav className="navbar">
        <div className="logo-section">
          <ShieldAlert size={28} color="#00ff41" />
          <h1>VAPTAI COMMAND</h1>
          <span className="beta-tag">ULTIMATE</span>
        </div>
        <div className="status-badge">
          <Activity size={14} className={loading ? "spin" : ""} />
          <span>{loading ? "ACTIVE SCAN" : "SYSTEM STANDBY"}</span>
        </div>
      </nav>

      <div className="main-layout">
        <aside className="sidebar">
          <h3><History size={14} /> Audit History</h3>
          <div className="history-list">
            {history.map((h) => (
              <div key={h.id} className="history-card" onClick={() => handleHistoryClick(h.id)}>
                <strong>{h.target}</strong>
                <span>{h.timestamp}</span>
              </div>
            ))}
          </div>
        </aside>

        <main className="content-area">
          <div className="search-container">
            <Search size={20} color="#8b949e" />
            <input
              placeholder="Assign target (domain/IP)..."
              value={target}
              onChange={(e) => {
                setTarget(e.target.value);
                if (activeTab === "cryptography") setActiveTab("vulnerabilities");
              }}
              disabled={loading}
            />
            <div className="mode-toggle">
              <button onClick={() => setScanMode("quick")} className={`mode-btn ${scanMode === "quick" ? "active" : ""}`}>QUICK</button>
              <button onClick={() => setScanMode("full")} className={`mode-btn ${scanMode === "full" ? "active" : ""}`}>DEEP</button>
            </div>
            <button onClick={() => handleScan()} disabled={loading} className="launch-btn" style={{ marginRight: "10px" }}>PROBE</button>
            <button onClick={() => setActiveTab("cryptography")} className={`tool-btn-dashboard ${activeTab === "cryptography" ? "active" : ""}`} title="Security Tools">
              <Shield size={18} />
            </button>
          </div>

          {error && (
            <div className="glass-card full-width" style={{ borderColor: "#f85149", marginBottom: "20px" }}>
              <strong style={{ color: "#f85149" }}>Error:</strong>
              <span style={{ marginLeft: "8px" }}>{error}</span>
            </div>
          )}

          {loading && <div className="loading-animation"><div className="spinner"></div><p className="neon-text">{scanStatus}</p></div>}

          {(scanData || activeTab === "cryptography") && (
            <div className="report-frame">
              {scanData && (
                <div className="hud-container">
                  <div className="hud-item"><label><MapPin size={12} /> Location</label><span>{geoData?.city}, {geoData?.country}</span></div>
                  <div className="hud-item"><label><Activity size={12} /> Latency</label><span>{healthData?.latency_ms} ms</span></div>
                  <div className="hud-item"><label><ShieldCheck size={12} /> Security</label><span style={{ color: healthData?.security_grade === "A" ? "#7ee787" : "#f85149" }}>Grade {healthData?.security_grade}</span></div>
                  <div className="hud-item"><label><Zap size={12} /> Threats</label><span>{scanData.filter((i) => String(i.risk_level || "").includes("CRITICAL")).length} Critical</span></div>
                  <button onClick={handleDownloadReport} className="report-download-btn" disabled={reportLoading}>
                    <FileText size={16} /> {reportLoading ? "GENERATING REPORT..." : "DOWNLOAD PDF REPORT"}
                  </button>
                </div>
              )}

              <div className="tab-bar">
                {scanData && <button onClick={() => setActiveTab("vulnerabilities")} className={`tab-item ${activeTab === "vulnerabilities" ? "active" : ""}`}>Findings</button>}
                {scanData && <button onClick={() => setActiveTab("infrastructure")} className={`tab-item ${activeTab === "infrastructure" ? "active" : ""}`}>Infrastructure</button>}
                {scanData && <button onClick={() => setActiveTab("ai")} className={`tab-item ${activeTab === "ai" ? "active" : ""}`}>AI Intelligence</button>}
                <button onClick={() => setActiveTab("cryptography")} className={`tab-item ${activeTab === "cryptography" ? "active" : ""}`}>Security Tools</button>
              </div>

              {activeTab === "vulnerabilities" && scanData && (
                <>
                  <div className="topology-view" style={{ marginBottom: "30px" }}>
                    <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} onNodeClick={(e, n) => setSelectedNodeInfo(n.data.fullData)} fitView>
                      <Background color="#111" gap={20} variant="dots" />
                      <Controls />
                    </ReactFlow>
                    {selectedNodeInfo && (
                      <div className="node-popover">
                        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "15px" }}>
                          <h4 style={{ margin: 0, color: "#58a6ff" }}>{String(selectedNodeInfo.service || "unknown").toUpperCase()}</h4>
                          <X size={18} onClick={() => setSelectedNodeInfo(null)} style={{ cursor: "pointer" }} />
                        </div>
                        <p style={{ fontSize: "0.75rem" }}><strong>Remediation:</strong> {selectedNodeInfo.remediation}</p>
                      </div>
                    )}
                  </div>

                  <div className="glass-card full-width">
                    <h3 style={{ display: "flex", alignItems: "center", gap: "10px" }}><AlertTriangle color="#f85149" /> Detailed Vulnerability Inventory</h3>
                    <table>
                      <thead>
                        <tr><th>Port</th><th>Service</th><th>Risk Level</th><th>Remediation Advice</th></tr>
                      </thead>
                      <tbody>
                        {scanData.map((item, i) => (
                          <tr key={i}>
                            <td className="mono">{item.port}</td>
                            <td className="service-tag">{item.service}</td>
                            <td className={String(item.risk_level || "").includes("CRITICAL") ? "risk-critical" : "risk-low"}>{item.risk_level}</td>
                            <td style={{ fontSize: "0.8rem", color: "#8b949e" }}>{item.remediation}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </>
              )}

              {activeTab === "infrastructure" && (
                <div className="infra-layout">
                  <div className="hud-container" style={{ marginBottom: "20px" }}>
                    <div className="hud-item"><label>ISP</label><span>{geoData?.isp || "Unknown"}</span></div>
                    <div className="hud-item"><label>Server Engine</label><span>{reconData?.tech?.server || "Hidden"}</span></div>
                    <div className="hud-item"><label>SSL Issuer</label><span>{sslData?.issuer || "N/A"}</span></div>
                    <div className="hud-item"><label>Days to Expiry</label><span>{sslData?.days_remaining} Days</span></div>
                  </div>

                  <div className="info-grid">
                    <div className="glass-card">
                      <h4><Database size={18} /> WHOIS Records</h4>
                      <div className="intel-list">
                        <p><Calendar size={12} /> <strong>Created:</strong> {reconData?.whois?.creation_date}</p>
                        <p><Calendar size={12} /> <strong>Expires:</strong> {reconData?.whois?.expiration_date}</p>
                        <p><Mail size={12} /> <strong>Registrar:</strong> {reconData?.whois?.registrar}</p>
                        <p><Globe size={12} /> <strong>Organization:</strong> {reconData?.whois?.org}</p>
                      </div>
                    </div>
                    <div className="glass-card">
                      <h4><Hash size={18} /> DNS Mapping</h4>
                      <div className="intel-list">
                        {Object.entries(reconData?.dns || {}).map(([k, v]) => (
                          <p key={k}><strong>{k}:</strong> {v.join(", ") || "N/A"}</p>
                        ))}
                      </div>
                    </div>
                    <div className="glass-card">
                      <h4><Shield size={18} /> Header Security (Missing)</h4>
                      <div className="intel-list">
                        {healthData?.missing_headers?.length ? healthData.missing_headers.map((mh) => (
                          <p key={mh} style={{ color: "#f85149" }}>✖ {mh}</p>
                        )) : <p style={{ color: "#7ee787" }}>✔ All core headers present</p>}
                      </div>
                    </div>
                    <div className="glass-card">
                      <h4><Zap size={18} /> Discovered Subdomains</h4>
                      <div className="intel-list scrollable">
                        {subdomains.map((s) => <p key={s.subdomain}>🌐 {s.subdomain} <span style={{ color: "#8b949e" }}>({s.ip})</span></p>)}
                        {subdomains.length === 0 && <p>No subdomains found.</p>}
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {activeTab === "ai" && scanData && (
                <div className="ai-report-frame">
                  {!aiReport ? (
                    <div style={{ textAlign: "center", padding: "60px" }}>
                      <Zap size={48} color="#d29922" style={{ marginBottom: "20px" }} />
                      <button onClick={handleAiAnalyze} disabled={aiLoading} className="launch-btn">GENERATE AI ANALYSIS</button>
                    </div>
                  ) : (
                    <div className="ai-glass-panel" style={{ whiteSpace: "pre-wrap" }}>{aiReport}</div>
                  )}
                </div>
              )}

              {activeTab === "cryptography" && (
                <div className="crypto-layout">
                  <div className="tab-bar" style={{ marginBottom: "25px", borderBottom: "none" }}>
                    <button onClick={() => setCryptoSubTab("integrity")} className={`tab-item ${cryptoSubTab === "integrity" ? "active" : ""}`} style={{ fontSize: "0.8rem" }}>
                      <Lock size={14} style={{ marginRight: "8px" }} /> Integrity
                    </button>
                    <button onClick={() => setCryptoSubTab("encryption")} className={`tab-item ${cryptoSubTab === "encryption" ? "active" : ""}`} style={{ fontSize: "0.8rem" }}>
                      <Zap size={14} style={{ marginRight: "8px" }} /> Encryption/AES
                    </button>
                    <button onClick={() => setCryptoSubTab("packet")} className={`tab-item ${cryptoSubTab === "packet" ? "active" : ""}`} style={{ fontSize: "0.8rem" }}>
                      <Activity size={14} style={{ marginRight: "8px" }} /> Packet Analyzer
                    </button>
                  </div>

                  {cryptoSubTab === "integrity" && (
                    <div className="glass-card full-width">
                      <div style={{ textAlign: "center", padding: "40px" }}>
                        <Lock size={48} color="#00ff41" style={{ marginBottom: "20px" }} />
                        <h2>File Integrity Checker</h2>
                        <p style={{ color: "#8b949e", marginBottom: "30px" }}>Calculate cryptographic fingerprints (MD5, SHA-1, SHA-256) to ensure file authenticity.</p>
                        <div className="file-upload-zone">
                          <input type="file" id="file-input" onChange={handleFileHash} style={{ display: "none" }} />
                          <label htmlFor="file-input" className="launch-btn" style={{ cursor: "pointer", display: "inline-flex", alignItems: "center", gap: "10px" }}>
                            <FileText size={18} /> {fileLoading ? "Calculating..." : "Upload for Hashing"}
                          </label>
                        </div>
                      </div>
                      {fileHashData && (
                        <div className="hash-results-container">
                          <div className="hash-item"><label>SHA-256</label><div className="hash-value mono">{fileHashData.sha256}</div></div>
                          <div className="hash-item"><label>MD5</label><div className="hash-value mono">{fileHashData.md5}</div></div>
                        </div>
                      )}
                    </div>
                  )}

                  {cryptoSubTab === "encryption" && (
                    <div className="glass-card full-width">
                      <div style={{ padding: "20px" }}>
                        <h2>AES-256 Symmetric Encryption</h2>
                        <p style={{ color: "#8b949e" }}>Securely encrypt or decrypt text using the industry-standard AES algorithm.</p>

                        <div style={{ marginTop: "20px" }}>
                          <textarea className="glass-input" placeholder="Enter text to encrypt/decrypt..." value={aesInput} onChange={(e) => setAesInput(e.target.value)} rows={4} style={{ width: "100%", marginBottom: "15px" }} />
                          <input className="glass-input" placeholder="Secret Key (Optional)..." value={aesKey} onChange={(e) => setAesKey(e.target.value)} style={{ width: "100%", marginBottom: "15px" }} />

                          <div style={{ display: "flex", gap: "10px" }}>
                            <button onClick={() => handleAes("encrypt")} className="launch-btn" style={{ background: "#58a6ff" }}>ENCRYPT AES</button>
                            <button onClick={() => handleAes("decrypt")} className="launch-btn" style={{ background: "#238636" }}>DECRYPT AES</button>
                            <button onClick={() => handleBase64("encode")} className="launch-btn" style={{ background: "#d29922" }}>B64 ENCODE</button>
                            <button onClick={() => handleBase64("decode")} className="launch-btn" style={{ background: "#d29922" }}>B64 DECODE</button>
                          </div>
                        </div>

                        {aesResult && (
                          <div className="hash-results-container" style={{ marginTop: "25px" }}>
                            <label style={{ fontSize: "0.7rem", color: "#8b949e" }}>RESULT</label>
                            <div className="hash-value mono" style={{ marginTop: "10px", color: "#fff" }}>{aesResult}</div>
                            <button
                              className="copy-btn"
                              onClick={async () => {
                                try {
                                  await navigator.clipboard.writeText(aesResult);
                                } catch {
                                  setError("Failed to copy to clipboard");
                                }
                              }}
                              style={{ marginTop: "10px" }}
                            >
                              COPY RESULT
                            </button>
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  {cryptoSubTab === "packet" && (
                    <div className="glass-card full-width">
                      <div style={{ textAlign: "center", padding: "40px" }}>
                        <Activity size={48} color="#f85149" style={{ marginBottom: "20px" }} />
                        <h2>Packet Inspector (Wireshark-lite)</h2>
                        <p style={{ color: "#8b949e", marginBottom: "30px" }}>Upload a .pcap or .pcapng file to perform deep packet inspection and traffic analysis.</p>
                        <div className="file-upload-zone">
                          <input type="file" id="pcap-input" onChange={handlePcapUpload} style={{ display: "none" }} />
                          <label htmlFor="pcap-input" className="launch-btn" style={{ cursor: "pointer", display: "inline-flex", alignItems: "center", gap: "10px", background: "#f85149" }}>
                            <Search size={18} /> {pcapLoading ? "Parsing PCAP..." : "Select PCAP File"}
                          </label>
                        </div>
                      </div>

                      {pcapData && (
                        <div className="pcap-results" style={{ marginTop: "20px" }}>
                          <h4>Captured Traffic Summary ({pcapData.count} Packets)</h4>
                          <div className="scrollable" style={{ maxHeight: "400px" }}>
                            <table>
                              <thead>
                                <tr><th>ID</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Length</th></tr>
                              </thead>
                              <tbody>
                                {(pcapData.packets || []).map((p) => (
                                  <tr key={p.id}>
                                    <td>{p.id}</td>
                                    <td className="mono" style={{ color: "#58a6ff" }}>{p.src}</td>
                                    <td className="mono" style={{ color: "#7ee787" }}>{p.dst}</td>
                                    <td className="service-tag">{p.proto}</td>
                                    <td>{p.len}</td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </main>
      </div>

      <div className={`chat-container ${chatOpen ? "open" : ""}`}>
        {chatOpen && (
          <div className="chat-box">
            <div className="chat-head"><span>AI FIELD AGENT</span> <X size={18} onClick={() => setChatOpen(false)} style={{ cursor: "pointer" }} /></div>
            <div className="chat-body">
              {chatMessages.map((m, i) => <div key={i} className={`message ${m.role}`}>{m.content}</div>)}
              <div ref={chatEndRef} />
            </div>
            <div className="chat-foot">
              <input value={chatInput} onChange={(e) => setChatInput(e.target.value)} onKeyDown={(e) => e.key === "Enter" && handleSendMessage()} placeholder="Ask intel..." />
              <button onClick={handleSendMessage} className="launch-btn"><Send size={16} /></button>
            </div>
          </div>
        )}
        {!chatOpen && <div className="chat-bubble" onClick={() => setChatOpen(true)}><Activity size={28} color="#fff" /></div>}
      </div>
    </div>
  );
}

export default App;
