import { useState, useEffect, useRef } from "react";
import axios from "axios";
import {
  ShieldAlert,
  Search,
  Server,
  Activity,
  Lock,
  History,
  FileText,
  Hash, // <--- NEW: Imported Hash Icon
} from "lucide-react";
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from "recharts";
import ReactFlow, { Background, Controls } from "reactflow";
import "reactflow/dist/style.css";
import "./App.css";

function App() {
  const [target, setTarget] = useState("");
  const [loading, setLoading] = useState(false);
  const [scanData, setScanData] = useState(null);
  const [history, setHistory] = useState([]);
  const [error, setError] = useState(null);
  const [integrityHash, setIntegrityHash] = useState(null);

  // --- NEW: Subdomain State ---
  const [subdomains, setSubdomains] = useState([]);

  // --- NEW: AI Report State ---
  const [aiReport, setAiReport] = useState(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [securityScore, setSecurityScore] = useState(null);

  // --- NEW: SecureChat State ---
  const [chatOpen, setChatOpen] = useState(false);
  const [chatInput, setChatInput] = useState("");
  const [chatMessages, setChatMessages] = useState([
    {
      role: "assistant",
      content:
        "Hi! I'm your VaptAI Security Assistant. Ask me anything about your scan results!",
    },
  ]);
  const [chatLoading, setChatLoading] = useState(false);

  // --- NEW: Scroll Ref ---
  const chatEndRef = useRef(null);

  // --- NEW: Status Polling State ---
  const [scanId, setScanId] = useState(null);
  const [scanMessage, setScanMessage] = useState("");

  // --- NEW: Auto-Patch State ---
  const [selectedVuln, setSelectedVuln] = useState(null);
  const [patchLoading, setPatchLoading] = useState(false);
  const [aiPatch, setAiPatch] = useState(null);
  const [patchModalOpen, setPatchModalOpen] = useState(false);

  const fetchHistory = async () => {
    try {
      const res = await axios.get("http://127.0.0.1:5000/api/history");
      setHistory(res.data);
    } catch (err) {
      console.error("Failed to load history");
    }
  };

  useEffect(() => {
    fetchHistory();
  }, []);

  // --- NEW: Scroll Effect ---
  useEffect(() => {
    if (chatEndRef.current) {
      chatEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [chatMessages]);

  const handleSendMessage = async () => {
    if (!chatInput.trim()) return;

    const userMsg = { role: "user", content: chatInput };
    setChatMessages((prev) => [...prev, userMsg]);
    setChatInput("");
    setChatLoading(true);

    try {
      const res = await axios.post("http://127.0.0.1:5000/api/chat", {
        message: chatInput,
        scan_context: {
          target: target,
          results: scanData,
          subdomains: subdomains,
        },
      });
      setChatMessages((prev) => [
        ...prev,
        { role: "assistant", content: res.data.response },
      ]);
    } catch (err) {
      setChatMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: "Sorry, I'm having trouble connecting right now.",
        },
      ]);
    } finally {
      setChatLoading(false);
    }
  };

  const handleAiAnalyze = async () => {
    if (!scanData) return;
    setAiLoading(true);
    try {
      const response = await axios.post(
        "http://127.0.0.1:5000/api/ai_analyze",
        {
          target: target,
          scan_data: scanData,
        },
      );
      setAiReport(response.data.ai_report);
      setSecurityScore(response.data.security_score);
    } catch (err) {
      console.error("AI Analysis Error", err);
    } finally {
      setAiLoading(false);
    }
  };

  // --- NEW: Polling Logic ---
  useEffect(() => {
    let interval;
    if (scanId && loading) {
      interval = setInterval(async () => {
        try {
          const res = await axios.get(
            `http://127.0.0.1:5000/api/scan_status/${scanId}`,
          );
          setScanMessage(res.data.message);

          if (res.data.status === "completed") {
            setScanData(res.data.scan_data);
            setSubdomains(res.data.subdomains || []);
            setIntegrityHash(res.data.integrity_hash);
            setLoading(false);
            setScanId(null);
            fetchHistory();
            clearInterval(interval);
          } else if (res.data.status === "failed") {
            setError(`Scan Failed: ${res.data.message}`);
            setLoading(false);
            setScanId(null);
            clearInterval(interval);
          }
        } catch (err) {
          console.error("Polling error", err);
        }
      }, 2000); // Poll every 2 seconds
    }
    return () => clearInterval(interval);
  }, [scanId, loading]);

  const handleScan = async () => {
    if (!target) return;
    setLoading(true);
    setError(null);
    setScanData(null);
    setSubdomains([]); // Clear previous subdomains
    setAiReport(null); // Reset AI report
    setSecurityScore(null); // Reset Score
    setIntegrityHash(null);
    setScanMessage("Requesting scan...");

    try {
      const response = await axios.post("http://127.0.0.1:5000/api/scan", {
        target: target,
      });
      setScanId(response.data.scan_id);
    } catch (err) {
      setError("Failed to initiate scan. Ensure Backend is running.");
      setLoading(false);
    }
  };

  const handleDownload = async () => {
    if (!scanData) return;
    try {
      const response = await axios.post(
        "http://127.0.0.1:5000/api/report",
        {
          target: target,
          scan_data: scanData,
          ai_report: aiReport,
          subdomains: subdomains,
        },
        { responseType: "blob" },
      );
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", `Report_${target}.pdf`);
      document.body.appendChild(link);
      link.click();
    } catch (err) {
      console.error("Download Error", err);
    }
  };

  // --- NEW: Handle Node Click ---
  const onNodeClick = (event, node) => {
    if (node.id.startsWith("port-")) {
      const index = parseInt(node.id.split("-")[1]);
      const vuln = scanData[index];
      setSelectedVuln(vuln);
      setPatchModalOpen(true);
      setAiPatch(null); // Reset patch when selecting new vuln
    }
  };

  // --- NEW: Generate Patch ---
  const handleGeneratePatch = async (vuln) => {
    setPatchLoading(true);
    try {
      const res = await axios.post("http://127.0.0.1:5000/api/generate_patch", {
        vulnerability: vuln,
      });
      setAiPatch(res.data.patch);
    } catch (err) {
      console.error("Patch Generation Error", err);
      setAiPatch("⚠️ Failed to generate patch.");
    } finally {
      setPatchLoading(false);
    }
  };

  // Calculate Stats for the Charts
  const riskStats = scanData
    ? [
        {
          name: "Critical",
          value: scanData.filter((i) => i.risk_level.includes("CRITICAL"))
            .length,
          color: "#da3633",
        },
        {
          name: "High",
          value: scanData.filter((i) => i.risk_level.includes("High")).length,
          color: "#bc8c00",
        },
        {
          name: "Low",
          value: scanData.filter((i) => i.risk_level === "Low").length,
          color: "#238636",
        },
      ].filter((item) => item.value > 0)
    : [];

  return (
    <div className="dashboard-container">
      {/* Navbar */}
      <header className="navbar">
        <div className="logo">
          <ShieldAlert size={32} color="#00ff41" />
          <h1>
            VaptAI <span className="beta">v2.0</span>
          </h1>
        </div>
        <div className="status">
          <Activity size={18} color="#00ff41" />
          <span>DB CONNECTED</span>
        </div>
      </header>

      <div className="main-layout">
        {/* SIDEBAR: HISTORY */}
        <aside className="history-panel">
          <h3>
            <History size={18} /> Recent Scans
          </h3>
          {history.length === 0 ? (
            <p className="empty-text">No scans yet.</p>
          ) : (
            <ul>
              {history.map((h) => (
                <li key={h.id} className="history-item">
                  <strong>{h.target}</strong>
                  <span>{h.timestamp}</span>
                  <span className="vuln-badge">{h.vuln_count} Assets</span>
                </li>
              ))}
            </ul>
          )}
        </aside>

        {/* MAIN CONTENT */}
        <div className="scanner-section">
          <div className="input-group">
            <Search className="search-icon" size={20} />
            <input
              type="text"
              placeholder="Target Domain (e.g. scanme.nmap.org)"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              disabled={loading}
            />
            <button onClick={handleScan} disabled={loading}>
              {loading ? "SCANNING..." : "START SCAN"}
            </button>
          </div>

          {error && <div className="error-card">{error}</div>}

          {loading && (
            <div className="loading-animation">
              <div className="spinner"></div>
              <p>{scanMessage || "Enumerating Attack Surface..."}</p>
            </div>
          )}

          {scanData && (
            <div className="report-card">
              <div className="report-header">
                {/* --- NEW: Wrapped Title and Hash in a Div --- */}
                <div>
                  <h2>
                    <Server size={20} /> Results: {target}
                  </h2>

                  {/* --- NEW: Forensic Integrity Badge --- */}
                  {integrityHash && (
                    <div
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: "8px",
                        fontSize: "0.8rem",
                        color: "#8b949e",
                        marginTop: "5px",
                        fontFamily: "monospace",
                        background: "#0d1117",
                        padding: "5px 10px",
                        borderRadius: "4px",
                        border: "1px solid #30363d",
                        width: "fit-content",
                      }}
                    >
                      <Hash size={14} color="#a5d6ff" />
                      <span>
                        EVIDENCE HASH (SHA256): {integrityHash.substring(0, 20)}
                        ...
                      </span>
                    </div>
                  )}
                </div>

                <button onClick={handleDownload} className="btn-download">
                  <FileText size={16} /> PDF Report
                </button>
              </div>

              <div
                className="analytics-dashboard"
                style={{ display: "flex", gap: "20px", marginBottom: "30px" }}
              >
                {/* Card 1: Risk Distribution Chart */}
                <div
                  className="chart-card"
                  style={{
                    flex: 1,
                    background: "#161b22",
                    padding: "20px",
                    borderRadius: "12px",
                    border: "1px solid #30363d",
                  }}
                >
                  <h3 style={{ marginTop: 0 }}>
                    🛡️ Vulnerability Distribution
                  </h3>
                  <div style={{ height: "250px" }}>
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={riskStats}
                          cx="50%"
                          cy="50%"
                          innerRadius={60}
                          outerRadius={80}
                          paddingAngle={5}
                          dataKey="value"
                        >
                          {riskStats.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={entry.color} />
                          ))}
                        </Pie>
                        <Tooltip
                          contentStyle={{
                            backgroundColor: "#0d1117",
                            border: "1px solid #30363d",
                          }}
                        />
                        <Legend />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                {/* Card 2: Executive Summary */}
                <div
                  className="summary-card"
                  style={{
                    flex: 1,
                    background: "#161b22",
                    padding: "20px",
                    borderRadius: "12px",
                    border: "1px solid #30363d",
                  }}
                >
                  <h3 style={{ marginTop: 0 }}>📊 Executive Summary</h3>
                  <div
                    style={{
                      display: "grid",
                      gridTemplateColumns: "1fr 1fr",
                      gap: "15px",
                    }}
                  >
                    <div className="stat-box">
                      <span style={{ color: "#8b949e" }}>Total Assets</span>
                      <h2 style={{ fontSize: "2rem", margin: "5px 0" }}>
                        {scanData.length}
                      </h2>
                    </div>
                    <div className="stat-box">
                      <span style={{ color: "#da3633" }}>Critical Threats</span>
                      <h2
                        style={{
                          fontSize: "2rem",
                          margin: "5px 0",
                          color: "#da3633",
                        }}
                      >
                        {
                          scanData.filter((i) =>
                            i.risk_level.includes("CRITICAL"),
                          ).length
                        }
                      </h2>
                    </div>
                    <div className="stat-box">
                      <span style={{ color: "#8b949e" }}>Security Score</span>
                      <h2
                        style={{
                          fontSize: "2rem",
                          margin: "5px 0",
                          color:
                            securityScore !== null
                              ? securityScore > 80
                                ? "#2ea043"
                                : securityScore > 50
                                  ? "#bc8c00"
                                  : "#da3633"
                              : "#2ea043",
                        }}
                      >
                        {securityScore !== null
                          ? securityScore
                          : Math.max(
                              0,
                              100 -
                                scanData.filter((i) =>
                                  i.risk_level.includes("CRITICAL"),
                                ).length *
                                  20,
                            )}
                      </h2>
                      {securityScore !== null && (
                        <span style={{ fontSize: "0.7rem", color: "#8b949e" }}>
                          AI CALCULATED
                        </span>
                      )}
                    </div>
                  </div>
                </div>
              </div>

              {/* --- REFINED: Interactive Topology Map --- */}
              <div
                className="topology-section"
                style={{
                  background: "#161b22",
                  padding: "20px",
                  borderRadius: "12px",
                  border: "1px solid #30363d",
                  marginBottom: "30px",
                  height: "500px",
                }}
              >
                <h3
                  style={{
                    marginTop: 0,
                    display: "flex",
                    alignItems: "center",
                    gap: "10px",
                  }}
                >
                  🕸️ Network Infrastructure Topology
                  <span
                    style={{
                      fontSize: "0.7rem",
                      color: "#8b949e",
                      fontWeight: "normal",
                    }}
                  >
                    (Interactive Graph)
                  </span>
                </h3>
                <div
                  style={{
                    width: "100%",
                    height: "420px",
                    background: "#0d1117",
                    borderRadius: "8px",
                    border: "1px solid #21262d",
                  }}
                >
                  <ReactFlow
                    nodes={[
                      {
                        id: "target",
                        data: { label: `🎯 ${target || "Target"}` },
                        position: { x: 400, y: 200 },
                        style: {
                          background: "#238636",
                          color: "#fff",
                          border: "2px solid #2ea043",
                          borderRadius: "8px",
                          padding: "10px",
                          fontWeight: "bold",
                          width: 180,
                        },
                      },
                      ...(subdomains || []).map((sub, i) => ({
                        id: `sub-${i}`,
                        data: { label: `🌐 ${sub.subdomain}` },
                        position: { x: 100 + i * 200, y: 50 },
                        style: {
                          background: "#1f6feb",
                          color: "#fff",
                          border: "none",
                          borderRadius: "6px",
                          fontSize: "0.75rem",
                          width: 150,
                        },
                      })),
                      ...(scanData || []).map((port, i) => {
                        const isCritical =
                          port.risk_level.includes("CRITICAL") ||
                          port.risk_level.includes("Nuclei: CRITICAL");
                        const isHigh =
                          port.risk_level.includes("High") ||
                          port.risk_level.includes("Nuclei: HIGH");
                        return {
                          id: `port-${i}`,
                          data: {
                            label: `🔌 Port ${port.port}\n(${port.service})`,
                          },
                          position: { x: 50 + i * 130, y: 350 },
                          style: {
                            background: isCritical
                              ? "#da3633"
                              : isHigh
                                ? "#bc8c00"
                                : "#30363d",
                            color: "#fff",
                            border: isCritical ? "2px solid #ff7b72" : "none",
                            borderRadius: "4px",
                            fontSize: "0.65rem",
                            width: 110,
                            whiteSpace: "pre-wrap",
                            cursor: "pointer",
                          },
                        };
                      }),
                    ]}
                    edges={[
                      ...(subdomains || []).map((_, i) => ({
                        id: `e-target-sub-${i}`,
                        source: "target",
                        target: `sub-${i}`,
                        animated: true,
                        label: "subdomain",
                        labelStyle: { fill: "#8b949e", fontSize: "0.6rem" },
                        style: { stroke: "#1f6feb", strokeWidth: 2 },
                      })),
                      ...(scanData || []).map((_, i) => ({
                        id: `e-target-port-${i}`,
                        source: "target",
                        target: `port-${i}`,
                        animated: false,
                        style: { stroke: "#30363d", strokeWidth: 1 },
                      })),
                    ]}
                    onNodeClick={onNodeClick}
                    fitView
                  >
                    <Background color="#161b22" gap={20} variant="dots" />
                    <Controls />
                  </ReactFlow>
                </div>
              </div>

              {/* --- NEW: Subdomains Section --- */}
              {subdomains.length > 0 && (
                <div
                  className="subdomain-section"
                  style={{
                    background: "#161b22",
                    padding: "20px",
                    borderRadius: "12px",
                    border: "1px solid #30363d",
                    marginBottom: "30px",
                  }}
                >
                  <h3
                    style={{
                      marginTop: 0,
                      display: "flex",
                      alignItems: "center",
                      gap: "10px",
                    }}
                  >
                    🌐 Discovered Subdomains
                    <span
                      style={{
                        fontSize: "0.8rem",
                        background: "#238636",
                        padding: "2px 8px",
                        borderRadius: "10px",
                      }}
                    >
                      {subdomains.length} Found
                    </span>
                  </h3>
                  <div
                    style={{
                      display: "grid",
                      gridTemplateColumns:
                        "repeat(auto-fill, minmax(200px, 1fr))",
                      gap: "10px",
                      marginTop: "15px",
                    }}
                  >
                    {subdomains.map((sub, idx) => (
                      <div
                        key={idx}
                        style={{
                          background: "#0d1117",
                          padding: "10px",
                          borderRadius: "6px",
                          border: "1px solid #30363d",
                          fontSize: "0.85rem",
                        }}
                      >
                        <div style={{ color: "#58a6ff", fontWeight: "bold" }}>
                          {sub.subdomain}
                        </div>
                        <div
                          style={{
                            color: "#8b949e",
                            fontSize: "0.75rem",
                            fontFamily: "monospace",
                          }}
                        >
                          {sub.ip}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* --- NEW: AI Analysis Section --- */}
              <div
                className="ai-section"
                style={{
                  background: "#0d1117",
                  padding: "20px",
                  borderRadius: "12px",
                  border: "1px solid #238636",
                  marginBottom: "30px",
                  position: "relative",
                }}
              >
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    marginBottom: "15px",
                  }}
                >
                  <h3 style={{ margin: 0, color: "#238636" }}>
                    🧠 VaptAI Security Insights
                  </h3>
                  <button
                    onClick={handleAiAnalyze}
                    disabled={aiLoading || aiReport}
                    className="btn-ai"
                    style={{
                      background: aiReport ? "#30363d" : "#238636",
                      color: "white",
                      border: "none",
                      padding: "8px 15px",
                      borderRadius: "6px",
                      cursor: "pointer",
                      display: "flex",
                      alignItems: "center",
                      gap: "8px",
                    }}
                  >
                    {aiLoading
                      ? "Generating..."
                      : aiReport
                        ? "Report Ready"
                        : "Generate AI Report"}
                  </button>
                </div>

                {aiLoading && (
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: "10px",
                      color: "#8b949e",
                    }}
                  >
                    <div className="spinner-small"></div>
                    <span>Gemini is analyzing attack vectors...</span>
                  </div>
                )}

                {aiReport && (
                  <div
                    className="ai-report-content"
                    style={{
                      color: "#c9d1d9",
                      fontSize: "0.95rem",
                      lineHeight: "1.6",
                      whiteSpace: "pre-wrap",
                    }}
                  >
                    {aiReport}
                  </div>
                )}
              </div>

              <div className="table-wrapper">
                <table>
                  <thead>
                    <tr>
                      <th>PORT</th>
                      <th>SERVICE</th>
                      <th>VERSION</th>
                      <th>RISK</th>
                      <th>ACTION</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scanData.map((item, index) => (
                      <tr key={index}>
                        <td className="mono">{item.port}</td>
                        <td className="service-tag">{item.service}</td>
                        <td className="mono">{item.version || "Unknown"}</td>
                        <td
                          className={
                            item.risk_level.includes("CRITICAL")
                              ? "risk-critical"
                              : "risk-low"
                          }
                        >
                          {item.risk_level.includes("CRITICAL") ? (
                            <Lock size={14} />
                          ) : null}
                          {item.risk_level}
                        </td>
                        <td>
                          <button
                            className="btn-patch"
                            onClick={() => {
                              setSelectedVuln(item);
                              setPatchModalOpen(true);
                              handleGeneratePatch(item);
                            }}
                            style={{
                              padding: "4px 8px",
                              fontSize: "0.75rem",
                              background: "#238636",
                              color: "white",
                              border: "none",
                              borderRadius: "4px",
                              cursor: "pointer",
                            }}
                          >
                            Generate Patch
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* --- NEW: SecureChat Floating Widget --- */}
      <div
        className={`chat-widget ${chatOpen ? "open" : ""}`}
        style={{
          position: "fixed",
          bottom: "30px",
          right: "30px",
          zIndex: 1000,
          display: "flex",
          flexDirection: "column",
          alignItems: "flex-end",
        }}
      >
        {chatOpen && (
          <div
            className="chat-window"
            style={{
              width: "350px",
              height: "450px",
              background: "#161b22",
              border: "1px solid #30363d",
              borderRadius: "12px",
              marginBottom: "15px",
              display: "flex",
              flexDirection: "column",
              boxShadow: "0 8px 24px rgba(0,0,0,0.5)",
              overflow: "hidden",
            }}
          >
            <div
              className="chat-header"
              style={{
                padding: "15px",
                background: "#0d1117",
                borderBottom: "1px solid #30363d",
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
              }}
            >
              <span style={{ fontWeight: "bold", color: "#00ff41" }}>
                🛡️ VaptAI Assistant
              </span>
              <button
                onClick={() => setChatOpen(false)}
                style={{
                  background: "transparent",
                  border: "none",
                  color: "#8b949e",
                  cursor: "pointer",
                }}
              >
                ✕
              </button>
            </div>

            <div
              className="chat-messages"
              style={{
                flex: 1,
                padding: "15px",
                overflowY: "auto",
                display: "flex",
                flexDirection: "column",
                gap: "10px",
              }}
            >
              {chatMessages.map((msg, idx) => (
                <div
                  key={idx}
                  style={{
                    alignSelf: msg.role === "user" ? "flex-end" : "flex-start",
                    background: msg.role === "user" ? "#1f6feb" : "#21262d",
                    padding: "8px 12px",
                    borderRadius: "12px",
                    maxWidth: "85%",
                    fontSize: "0.85rem",
                    color: "#fff",
                  }}
                >
                  {msg.content}
                </div>
              ))}
              {chatLoading && (
                <div
                  className="spinner-small"
                  style={{ margin: "0 auto" }}
                ></div>
              )}
              <div ref={chatEndRef} />
            </div>

            <div
              className="chat-input-area"
              style={{
                padding: "15px",
                borderTop: "1px solid #30363d",
                display: "flex",
                gap: "10px",
              }}
            >
              <input
                type="text"
                placeholder="Ask about vulnerabilities..."
                value={chatInput}
                onChange={(e) => setChatInput(e.target.value)}
                onKeyPress={(e) => e.key === "Enter" && handleSendMessage()}
                style={{
                  background: "#0d1117",
                  border: "1px solid #30363d",
                  padding: "8px",
                  borderRadius: "4px",
                  flex: 1,
                  color: "#fff",
                }}
              />
              <button
                onClick={handleSendMessage}
                style={{
                  padding: "8px 12px",
                  background: "#238636",
                  borderRadius: "4px",
                }}
              >
                ➤
              </button>
            </div>
          </div>
        )}
        <button
          onClick={() => setChatOpen(!chatOpen)}
          className="chat-toggle-btn"
          style={{
            width: "60px",
            height: "60px",
            borderRadius: "50%",
            background: "#238636",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            boxShadow: "0 4px 12px rgba(0,0,0,0.3)",
            cursor: "pointer",
            border: "none",
            transition: "transform 0.2s",
          }}
          onMouseOver={(e) => (e.currentTarget.style.transform = "scale(1.1)")}
          onMouseOut={(e) => (e.currentTarget.style.transform = "scale(1)")}
        >
          <Activity size={28} color="#fff" />
        </button>
      </div>

      {/* --- NEW: Auto-Patch Modal --- */}
      {patchModalOpen && (
        <div
          className="modal-overlay"
          style={{
            position: "fixed",
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: "rgba(0,0,0,0.8)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 2000,
          }}
          onClick={() => setPatchModalOpen(false)}
        >
          <div
            className="modal-content"
            style={{
              background: "#161b22",
              width: "80%",
              maxWidth: "800px",
              maxHeight: "80vh",
              borderRadius: "12px",
              border: "1px solid #30363d",
              padding: "25px",
              overflowY: "auto",
              position: "relative",
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                marginBottom: "20px",
                borderBottom: "1px solid #30363d",
                paddingBottom: "15px",
              }}
            >
              <h2 style={{ margin: 0, color: "#2ea043" }}>
                🛠️ AI Remediation Patch
              </h2>
              <button
                onClick={() => setPatchModalOpen(false)}
                style={{
                  background: "transparent",
                  border: "none",
                  color: "#8b949e",
                  fontSize: "1.5rem",
                  cursor: "pointer",
                }}
              >
                ✕
              </button>
            </div>

            {selectedVuln && (
              <div
                style={{
                  background: "#0d1117",
                  padding: "15px",
                  borderRadius: "8px",
                  border: "1px solid #21262d",
                  marginBottom: "20px",
                }}
              >
                <div style={{ fontSize: "0.9rem", color: "#8b949e" }}>
                  Targeting Vulnerability:
                </div>
                <div style={{ fontWeight: "bold", color: "#f85149" }}>
                  Port {selectedVuln.port} - {selectedVuln.service} (
                  {selectedVuln.risk_level})
                </div>
              </div>
            )}

            {!aiPatch && !patchLoading && (
              <div style={{ textAlign: "center", padding: "40px" }}>
                <button
                  onClick={() => handleGeneratePatch(selectedVuln)}
                  style={{
                    padding: "12px 24px",
                    background: "#238636",
                    color: "white",
                    border: "none",
                    borderRadius: "6px",
                    fontSize: "1rem",
                    cursor: "pointer",
                  }}
                >
                  Generate Code-Level Patch
                </button>
              </div>
            )}

            {patchLoading && (
              <div
                style={{
                  textAlign: "center",
                  padding: "40px",
                  color: "#8b949e",
                }}
              >
                <div
                  className="spinner"
                  style={{ margin: "0 auto 15px" }}
                ></div>
                <p>AI is crafting your security patch...</p>
              </div>
            )}

            {aiPatch && (
              <div
                className="patch-content"
                style={{
                  color: "#c9d1d9",
                  fontSize: "0.95rem",
                  lineHeight: "1.6",
                  whiteSpace: "pre-wrap",
                  background: "#0d1117",
                  padding: "20px",
                  borderRadius: "8px",
                  border: "1px solid #30363d",
                  fontFamily: "monospace",
                }}
              >
                {aiPatch}
                <div style={{ marginTop: "20px", textAlign: "right" }}>
                  <button
                    onClick={() => {
                      navigator.clipboard.writeText(aiPatch);
                      alert("Patch copied to clipboard!");
                    }}
                    style={{
                      padding: "8px 15px",
                      background: "#1f6feb",
                      color: "white",
                      border: "none",
                      borderRadius: "6px",
                      cursor: "pointer",
                    }}
                  >
                    Copy to Clipboard
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
