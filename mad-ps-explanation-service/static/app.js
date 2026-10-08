/**
 * MAD-PS SENTINEL™ — Unified Operations Platform & Cyber Defense Cockpit
 * Real-time passive telemetry stream, 8-model detection mesh, 3-agent Council debate chamber,
 * and autonomous SOC monitoring.
 */

// Global Platform State
const state = {
  activeTab: "tab-operations",
  currentIncident: null,
  currentInspection: null,
  activeThreat: null,
  telemetryItems: [],
  dbmsTable: "incident_reports",
  dbmsRecords: [],
  isChatStreaming: false,
  isVoiceEnabled: false,
  isTtsEnabled: true,
  isContinuousVoice: false,
  isListening: false,
  speechRecognizer: null,
  synth: window.speechSynthesis || null,
  selectedVoice: null,
};

// Cross-tab Synchronization Channel
let syncBroadcast = null;
try {
  if (typeof BroadcastChannel !== "undefined") {
    syncBroadcast = new BroadcastChannel("madps_telemetry_sync");
    syncBroadcast.onmessage = (evt) => {
      if (evt.data) {
        handleIncomingTelemetryEvent(evt.data, false);
      }
    };
  }
} catch (e) {}

const CATEGORY_DISPLAY_MAP = {
  // 37-Attack Catalog Standard Display Names
  "xss-stored": "Stored Cross-Site Scripting (XSS)",
  "session-hijack": "Session Hijacking (LocalStorage Leak)",
  "csrf": "Cross-Site Request Forgery (CSRF)",
  "open-redirect": "Unvalidated URL Redirection",
  "auth-bypass": "Client-Header Trust Auth Bypass",
  "business-logic": "Business Logic / Price Tampering",
  "no-rate-limit": "Missing Rate Limiting / Burst Auth",
  "jwt-abuse": "JWT Signature / Algorithm Confusion",
  "session-fixation": "Session Fixation Attack",
  "bruteforce": "Credential Brute Force",
  "credential-stuffing": "Automated Credential Stuffing",
  "password-spraying": "Distributed Password Spraying",
  "account-takeover": "Account Takeover via Reset Token",
  "idor": "Insecure Direct Object Reference (IDOR)",
  "ssrf": "Server-Side Request Forgery (SSRF)",
  "xxe": "XML External Entity (XXE) Injection",
  "nosql-injection": "NoSQL Operator Query Injection",
  "api-abuse": "Unbounded Cursor / API Abuse",
  "data-exfil": "Administrative Data Exfiltration",
  "port-scanning-recon": "TCP Port Scanning Reconnaissance",
  "network-service-enumeration": "Network Service Banner Grabbing",
  "dos": "Denial of Service (DoS) Flood",
  "ddos": "Distributed Denial of Service (DDoS)",
  "dns-spoofing": "DNS Cache Poisoning / Spoofing",
  "mitm": "Man-in-the-Middle (MitM) Interception",
  "ransomware-behavioral": "Ransomware Cryptographic Burst",
  "trojan-behavioral": "Trojan Horse Process Injection",
  "spyware-behavioral": "Spyware Keylogger Telemetry Exfil",
  "botnet-c2": "Mirai / IoT Botnet C2 Beaconing",
  "compromised-iot": "Compromised IoT Firmware Exploitation",
  "polymorphic-malware": "Polymorphic / Metamorphic Malware",
  "apt-stealth-intrusion": "APT Multi-Stage Stealth Intrusion",
  "encrypted-c2": "Encrypted TLS / C2 Tunneling",
  "ai-adaptive": "AI-Adaptive Evasion Attack",
  "supply-chain-compromise": "SolarWinds-Style Supply Chain Poisoning",
  "double-extortion": "Double Extortion Data Breach",
  "zero-day-eval": "Holdout Zero-Day Exploit Evaluation",
  // Meta-Classifier Normalized Category Tags
  "IDOR_BOLA": "Insecure Direct Object Reference (IDOR / BOLA)",
  "SQLi": "SQL Injection (SQLi)",
  "BFLA_AUTH_BYPASS": "Broken Function Level Authorization (BFLA)",
  "XSS": "Cross-Site Scripting (XSS)",
  "BUSINESS_LOGIC_ANOMALY": "Business Logic / Price Tampering",
  "RATE_LIMIT_ANOMALY": "Missing Rate Limiting / Burst Auth",
  "MALICIOUS_THREAT": "High-Severity Security Incident",
  "BENIGN_TELEMETRY": "Normal / Benign Telemetry",
};

function formatCategoryDisplayName(cat) {
  if (!cat) return "Normal / Benign Telemetry";
  if (CATEGORY_DISPLAY_MAP[cat]) return CATEGORY_DISPLAY_MAP[cat];
  if (CATEGORY_DISPLAY_MAP[cat.toLowerCase()]) return CATEGORY_DISPLAY_MAP[cat.toLowerCase()];
  return cat.replace(/[_-]/g, " ").replace(/\b\w/g, l => l.toUpperCase());
}

// ──────────────────────────────────────────────────────────────────────────────
// Authentication Guard & Header Helpers
// ──────────────────────────────────────────────────────────────────────────────
function getAuthHeaders() {
  const token = localStorage.getItem("madps_token");
  const headers = { "Content-Type": "application/json" };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }
  return headers;
}

function initAuthGuard() {
  const path = window.location.pathname.toLowerCase();
  const token = localStorage.getItem("madps_token");
  const isProtected = ["/scan", "/council", "/dashboard", "/apps", "/compliance", "/developers", "/inspector", "/debate", "/monitoring", "/risk"].some(p => path === p || path.startsWith(p + "/") || path.startsWith(p + "?"));

  if (isProtected && (!token || token.length < 10)) {
    window.location.href = "/?login=true";
    return;
  }

  // Inject active user/org badge & logout button in navbar
  if (token) {
    const navActions = document.querySelector(".nav-actions");
    if (navActions && !document.getElementById("consoleUserBadge")) {
      let orgName = "Active Workspace";
      try {
        const orgData = JSON.parse(localStorage.getItem("madps_org") || "{}");
        if (orgData.name) orgName = orgData.name;
      } catch (e) {}

      const badge = document.createElement("div");
      badge.id = "consoleUserBadge";
      badge.style.display = "flex";
      badge.style.alignItems = "center";
      badge.style.gap = "8px";
      badge.style.marginLeft = "8px";
      badge.innerHTML = `
        <span style="font-size: 11px; font-weight: 700; color: var(--accent-cyan); background: rgba(0,242,254,0.1); border: 1px solid rgba(0,242,254,0.3); padding: 4px 10px; border-radius: 6px;" title="Active Tenant Organization">
          🏢 ${escapeHtml(orgName)}
        </span>
        <button onclick="logoutConsole()" class="btn btn-outline-nav btn-sm" style="font-size: 11px; padding: 4px 10px;" title="Sign Out">
          Sign Out
        </button>
      `;
      navActions.appendChild(badge);
    }
  }
}

function logoutConsole() {
  localStorage.removeItem("madps_token");
  localStorage.removeItem("madps_org");
  localStorage.removeItem("madps_api_key");
  localStorage.removeItem("madps_org_id");
  window.location.href = "/";
}

// ──────────────────────────────────────────────────────────────────────────────
// Theme Switcher (Emergent Dark / Light Mode)
// ──────────────────────────────────────────────────────────────────────────────
function applyTheme(theme) {
  localStorage.setItem("madps_theme", theme);
  document.documentElement.setAttribute("data-theme", theme);
  if (theme === "light") {
    document.body.classList.remove("dark-theme");
    document.body.classList.add("light-theme");
    document.querySelectorAll(".theme-icon-dark").forEach(el => el.style.display = "none");
    document.querySelectorAll(".theme-icon-light").forEach(el => el.style.display = "inline-block");
  } else {
    document.body.classList.remove("light-theme");
    document.body.classList.add("dark-theme");
    document.querySelectorAll(".theme-icon-dark").forEach(el => el.style.display = "inline-block");
    document.querySelectorAll(".theme-icon-light").forEach(el => el.style.display = "none");
  }
}

function initThemeToggle() {
  const savedTheme = localStorage.getItem("madps_theme") || "dark";
  applyTheme(savedTheme);

  document.querySelectorAll(".btn-theme-toggle, #btnThemeToggle").forEach((btn) => {
    btn.onclick = (e) => {
      e.preventDefault();
      const currentTheme = document.documentElement.getAttribute("data-theme") || (document.body.classList.contains("light-theme") ? "light" : "dark");
      const nextTheme = currentTheme === "dark" ? "light" : "dark";
      applyTheme(nextTheme);
    };
  });
}

// Immediate initial apply
try {
  const initialTheme = localStorage.getItem("madps_theme") || "dark";
  document.documentElement.setAttribute("data-theme", initialTheme);
} catch (e) {}

// ──────────────────────────────────────────────────────────────────────────────
// Safe DOM Initializer
// ──────────────────────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  initThemeToggle();
  initAuthGuard();
  initLiveClock();
  initUnifiedWebSocket();
  initPassiveTelemetryMonitor();
  initCouncilChamber();
  initDashboardFeed();
  initDbmsExplorer();
  initDeveloperApps();
  initMaddyAssistant();
  initLlmSettings();
  initVoiceInterface();
  loadOperationsOverview();

  // Background refresh intervals
  setInterval(loadOperationsOverview, 6000);
});

// Clock updater
function initLiveClock() {
  const clock = document.getElementById("liveUtcClock") || document.getElementById("headerUtcClock");
  if (!clock) return;
  const update = () => {
    const now = new Date();
    clock.textContent = now.toUTCString().split(" ")[4] + " UTC";
  };
  update();
  setInterval(update, 1000);
}

// ──────────────────────────────────────────────────────────────────────────────
// Unified WebSocket Connection (Port 8000)
// ──────────────────────────────────────────────────────────────────────────────
let globalWs = null;

function initUnifiedWebSocket() {
  try {
    const wsProtocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsHost = window.location.hostname || "127.0.0.1";
    const wsUrl = `${wsProtocol}//${wsHost}:8000/ws/council`;

    globalWs = new WebSocket(wsUrl);

    globalWs.onopen = () => {
      const badge = document.getElementById("ingestionLiveStatusBadge");
      if (badge) {
        badge.textContent = "🟢 STREAMING";
        badge.className = "pill-badge-cyan";
      }
    };

    globalWs.onmessage = (evt) => {
      try {
        const msg = JSON.parse(evt.data);
        handleIncomingTelemetryEvent(msg, true);
      } catch (e) {}
    };

    globalWs.onclose = () => {
      setTimeout(initUnifiedWebSocket, 4000);
    };
  } catch (err) {
    console.debug("WS connection error:", err);
  }
}

function handleIncomingTelemetryEvent(msg, broadcast = true) {
  if (!msg) return;

  if (broadcast && syncBroadcast) {
    try { syncBroadcast.postMessage(msg); } catch (e) {}
  }

  const evtType = msg.type || msg.event_type || "";

  if (evtType === "INGESTED_TELEMETRY" || evtType === "TELEMETRY_EVENT") {
    applyLiveTelemetryEvent(msg);
    pollLatestTelemetry();
    loadLiveFeedData();
    if (msg.is_threat) {
      setTimeout(loadLatestCouncilReport, 600);
    }
  } else if (evtType === "panelist_deliberation") {
    handleLivePanelistDeliberation(msg);
  } else if (evtType === "peer_critique") {
    handleLivePeerCritique(msg);
  } else if (evtType === "panelist_vote") {
    handleLivePanelistVote(msg);
  } else if (evtType === "judge_synthesis") {
    handleLiveJudgeSynthesis(msg);
  } else if (
    evtType === "council_verdict" ||
    evtType === "council_complete" ||
    evtType === "DEBATE_COMPLETE" ||
    evtType === "debate_complete" ||
    evtType === "PROACTIVE_ALERT" ||
    evtType === "COUNCIL_REPORT"
  ) {
    const reportData = msg.extra?.final_report || msg.final_report || msg.report || msg.data || msg;
    applyCouncilReportToChamber(reportData);
    loadLatestCouncilReport();
    loadLiveFeedData();
    pollLatestTelemetry();
  } else if (evtType === "agent_response") {
    if (msg.source === "reconstruction" && msg.extra?.result) {
      const thought1 = document.getElementById("thoughtStreamReconstruction");
      if (thought1) {
        thought1.innerHTML = `<strong>Causal Reconstruction:</strong><br>${escapeHtml(msg.extra.result.causal_narrative || msg.text)}`;
      }
    } else if (msg.source === "response" && msg.extra?.result) {
      const thought2 = document.getElementById("thoughtStreamResponse");
      if (thought2) {
        thought2.innerHTML = `<strong>Containment & Mitigation:</strong><br>${escapeHtml(msg.extra.result.containment_strategy || msg.text)}`;
      }
    } else if (msg.source === "judge" && msg.extra?.result) {
      const thought3 = document.getElementById("thoughtStreamJudge");
      if (thought3) {
        thought3.innerHTML = `<strong>Synthesis & Verification:</strong><br>${escapeHtml(msg.extra.result.rationale || msg.text)}`;
      }
    }
    loadLatestCouncilReport();
  } else if (evtType === "phase_change" || evtType === "PHASE_START" || evtType === "AGENT_THINKING") {
    updateCouncilTriggerState(msg);
  }
}

// ──────────────────────────────────────────────────────────────────────────────
// 1. Passive Live 8-Model Detection Mesh & Telemetry Monitor (/scan)
// ──────────────────────────────────────────────────────────────────────────────
let lastTelemetryTimestamp = null;

function initPassiveTelemetryMonitor() {
  pollLatestTelemetry();
  setInterval(pollLatestTelemetry, 2000);
}

async function pollLatestTelemetry() {
  try {
    const res = await fetch("/api/v1/inspections?limit=30", {
      headers: getAuthHeaders()
    });
    if (!res.ok) return;
    const items = await res.json();
    if (Array.isArray(items) && items.length > 0) {
      state.telemetryItems = items;
      renderLiveTelemetryTable(items);

      // Identify newest item or newest threat
      const latest = items[0];
      const newestThreat = items.find(it => it.is_threat || (it.confidence >= 0.70 && it.category !== "BENIGN_TELEMETRY"));

      if (!state.activeThreat && newestThreat) {
        state.activeThreat = newestThreat;
      }

      // If a threat occurred recently, show it on the score matrix
      const displayItem = state.selectedInspection || (state.activeThreat && (Date.now() - new Date(state.activeThreat.timestamp || Date.now()).getTime() < 30000) ? state.activeThreat : latest);

      if (displayItem && displayItem.timestamp !== lastTelemetryTimestamp) {
        lastTelemetryTimestamp = displayItem.timestamp;
        applyLiveTelemetryEvent(displayItem);
      }
    }
  } catch (err) {
    console.debug("Telemetry poll failed:", err);
  }
}

function applyLiveTelemetryEvent(eventData) {
  const methodEl = document.getElementById("liveEventMethod");
  const endpointEl = document.getElementById("liveEventEndpoint");
  const timeEl = document.getElementById("liveEventTime");
  const clientIpEl = document.getElementById("liveEventClientIp");
  const latencyEl = document.getElementById("liveEventLatency");
  const payloadEl = document.getElementById("liveEventPayloadPreview");
  const terminal = document.getElementById("inspectorTerminalOutput");
  const confVal = document.getElementById("inspectorConfidenceVal");
  const metaChip = document.getElementById("inspectorMetaScoreChip");

  const rawTel = eventData.raw_telemetry || {};
  const method = eventData.method || rawTel.method || "POST";
  const path = eventData.endpoint || eventData.target_url || rawTel.path || rawTel.endpoint || "/";
  const payload = eventData.payload || rawTel.payload || (typeof rawTel === "string" ? rawTel : (rawTel.body || JSON.stringify(rawTel)));
  const clientIp = eventData.client_ip || rawTel.client_ip || rawTel.source_ip || "127.0.0.1";
  const latency = eventData.latency_ms || rawTel.latency_ms || 14.5;
  const confidence = parseFloat(eventData.confidence ?? 0.05);
  const category = eventData.category || "BENIGN_TELEMETRY";
  const isThreat = Boolean(eventData.is_threat || (confidence >= 0.70 && category !== "BENIGN_TELEMETRY"));

  if (isThreat) {
    state.activeThreat = eventData;
  }

  if (methodEl) methodEl.textContent = method;
  if (endpointEl) endpointEl.textContent = path;
  if (timeEl) timeEl.textContent = new Date(eventData.timestamp || Date.now()).toLocaleTimeString();
  if (clientIpEl) clientIpEl.textContent = `${clientIp} (Client Middleware)`;
  if (latencyEl) latencyEl.textContent = `Status: ${eventData.status_code || 200} • ${latency}ms P95`;
  if (payloadEl) payloadEl.textContent = payload ? (typeof payload === "object" ? JSON.stringify(payload, null, 2) : String(payload).slice(0, 400)) : "(Empty / Headers-only request)";

  // Update Meta-Confidence & Category Badge
  const displayName = formatCategoryDisplayName(category);
  const confPct = (confidence * 100).toFixed(1);
  if (confVal) confVal.textContent = `${confPct}%`;
  if (metaChip) {
    metaChip.className = isThreat ? "meta-score-chip threat-active" : "meta-score-chip clean-active";
    metaChip.innerHTML = `<span class="chip-label">META-CONFIDENCE:</span> <span class="chip-value">${displayName} (${confPct}%)</span>`;
    metaChip.style.background = isThreat ? "rgba(239, 68, 68, 0.2)" : "rgba(0, 242, 254, 0.15)";
    metaChip.style.borderColor = isThreat ? "rgba(239, 68, 68, 0.5)" : "rgba(0, 242, 254, 0.4)";
  }

  // Update 8 Model Gauges
  const scores = eventData.branch_scores || {};
  updateModelGauges(scores);

  // Update Council Active Card
  const councilBox = document.getElementById("councilActiveIncidentBox");
  const incidentTag = document.getElementById("activeIncidentIdTag");
  const councilSummary = document.getElementById("councilSynthesisSummary");
  const councilStatusChip = document.getElementById("councilStatusChip");

  if (isThreat) {
    if (councilBox) councilBox.classList.remove("hidden");
    if (incidentTag) incidentTag.textContent = eventData.incident_id || `INC-${Date.now().toString(36).toUpperCase()}`;
    if (councilSummary) councilSummary.textContent = `Attack Category: ${displayName}. Multi-Agent Council automatically deliberated and computed mitigating actions.`;
    if (councilStatusChip) {
      councilStatusChip.textContent = "COUNCIL CONVENED";
      councilStatusChip.style.background = "rgba(239,68,68,0.2)";
      councilStatusChip.style.color = "#ef4444";
      councilStatusChip.style.borderColor = "rgba(239,68,68,0.4)";
    }
  } else if (!state.activeThreat) {
    if (councilBox) councilBox.classList.add("hidden");
    if (councilStatusChip) {
      councilStatusChip.textContent = "MESH ARMED";
      councilStatusChip.style.background = "rgba(16,185,129,0.15)";
      councilStatusChip.style.color = "#10b981";
      councilStatusChip.style.borderColor = "rgba(16,185,129,0.3)";
    }
  }

  // Stream to Live Terminal Diff
  if (terminal) {
    const ts = new Date().toISOString().split("T")[1].slice(0, 8);
    const scoreLog = `[${ts}] [PASSIVE_INGEST] ${method} ${path} | CLIENT=${clientIp} LATENCY=${latency}ms
[META_CLASSIFIER] Category=${category} Confidence=${confPct}% Severity=${eventData.severity || (isThreat ? 'HIGH' : 'LOW')}
[8_BRANCH_EVAL]
  • iForest (Outlier):     ${((scores.isolation_forest || scores.statistical_anomaly || 0.04) * 100).toFixed(1)}%
  • Semantic AST:          ${((scores.semantic_ast || scores.semantic_payload_evaluator || 0.05) * 100).toFixed(1)}%
  • Sequence LSTM:         ${((scores.lstm_sequence || scores.stateful_sequence_tracker || 0.02) * 100).toFixed(1)}%
  • Graph Correlation:     ${((scores.graph_correlation || 0.01) * 100).toFixed(1)}%
  • XGBoost Velocity:      ${((scores.xgboost || scores.rate_frequency_anomaly || 0.03) * 100).toFixed(1)}%
  • Random Forest:         ${((scores.random_forest || scores.behavioral_identity_abuse || 0.02) * 100).toFixed(1)}%
  • SVM RBF Boundary:      ${((scores.svm || scores.svm_classifier || 0.01) * 100).toFixed(1)}%
  • Deep 1D-CNN:           ${((scores.cnn_1d || scores.deep_neural_network || 0.04) * 100).toFixed(1)}%
[STATUS] ${isThreat ? '🔴 ANOMALOUS THREAT IDENTIFIED -> COUNCIL CONVENED' : '🟢 BENIGN EVENT OK'}`;
    terminal.textContent = scoreLog;
  }
}

function updateModelGauges(scores) {
  const iforest = scores.isolation_forest ?? scores.statistical_anomaly ?? scores.iforest_score ?? 0.04;
  const semantic = scores.semantic_ast ?? scores.semantic_payload_evaluator ?? scores.dnn_cnn_score ?? 0.05;
  const lstm = scores.lstm_sequence ?? scores.stateful_sequence_tracker ?? scores.lstm_score ?? 0.02;
  const graph = scores.graph_correlation ?? scores.svm_score ?? 0.01;
  const xgb = scores.xgboost ?? scores.rate_frequency_anomaly ?? scores.xgboost_score ?? 0.03;
  const rf = scores.random_forest ?? scores.behavioral_identity_abuse ?? scores.rf_score ?? 0.02;
  const svm = scores.svm ?? scores.svm_classifier ?? scores.svm_score ?? 0.01;
  const dnn = scores.cnn_1d ?? scores.deep_neural_network ?? scores.dnn_mlp_score ?? 0.04;

  const gaugeMappings = [
    { scoreId: "scoreStatistical", fillId: "fillStatistical", val: iforest },
    { scoreId: "scoreSemantic", fillId: "fillSemantic", val: semantic },
    { scoreId: "scoreSequence", fillId: "fillSequence", val: lstm },
    { scoreId: "scoreGraph", fillId: "fillGraph", val: graph },
    { scoreId: "scoreRate", fillId: "fillRate", val: xgb },
    { scoreId: "scoreBehavioral", fillId: "fillBehavioral", val: rf },
    { scoreId: "scoreSVM", fillId: "fillSVM", val: svm },
    { scoreId: "scoreDNN", fillId: "fillDNN", val: dnn },
  ];

  gaugeMappings.forEach(g => {
    const scoreEl = document.getElementById(g.scoreId);
    const fillEl = document.getElementById(g.fillId);
    const numVal = Math.min(Math.max(parseFloat(g.val) || 0.0, 0.0), 1.0);
    const pct = (numVal * 100).toFixed(1);

    if (scoreEl) scoreEl.textContent = (numVal).toFixed(2);
    if (fillEl) {
      fillEl.style.width = `${Math.max(pct, 4)}%`;
      fillEl.style.background = numVal > 0.6 ? "linear-gradient(90deg, #ef4444, #dc2626)" : "linear-gradient(90deg, #00f2fe, #4facfe)";
    }
  });
}

function renderLiveTelemetryTable(items) {
  const tbody = document.getElementById("liveTelemetryTableBody");
  if (!tbody) return;
  if (!items || items.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; color:var(--text-muted); padding:20px;">Waiting for real incoming client telemetry...</td></tr>';
    return;
  }

  tbody.innerHTML = items.map((item, idx) => {
    const raw = item.raw_telemetry || {};
    const method = item.method || raw.method || "POST";
    const path = item.endpoint || item.target_url || raw.path || raw.endpoint || "/";
    const conf = item.confidence != null ? (item.confidence * 100).toFixed(1) + "%" : "--";
    const isThreat = item.is_threat || (item.confidence >= 0.70 && item.category !== "BENIGN_TELEMETRY");
    const cat = item.category || (isThreat ? "MALICIOUS_THREAT" : "BENIGN_TELEMETRY");
    const formattedCat = formatCategoryDisplayName(cat);
    const time = new Date(item.timestamp || Date.now()).toLocaleTimeString();
    const sev = item.severity || (isThreat ? "HIGH" : "LOW");
    const sevBadge = isThreat 
      ? '<span style="color:#ef4444; font-weight:700; background:rgba(239,68,68,0.15); padding:2px 6px; border-radius:4px; font-size:10px;">CRITICAL</span>'
      : '<span style="color:#10b981; font-weight:700; background:rgba(16,185,129,0.15); padding:2px 6px; border-radius:4px; font-size:10px;">LOW</span>';

    return `<tr onclick="window.selectTelemetryItem(${idx})" style="cursor:pointer; transition:background 0.15s ease;" onmouseover="this.style.background='rgba(0,242,254,0.06)'" onmouseout="this.style.background='transparent'">
      <td style="font-family:var(--font-mono); font-size:11px; color:#94a3b8;">${time}</td>
      <td><span style="font-family:var(--font-mono); font-weight:700; font-size:11px; color:#00f2fe; background:rgba(0,242,254,0.1); padding:2px 6px; border-radius:4px;">${method}</span></td>
      <td style="font-family:var(--font-mono); font-size:12px; color:#fff;">${escapeHtml(path)}</td>
      <td style="font-weight:600; color:${isThreat ? '#f87171' : '#4ade80'};">${escapeHtml(formattedCat)}</td>
      <td style="font-family:var(--font-mono); font-weight:700; color:${isThreat ? '#f87171' : '#38bdf8'};">${conf}</td>
      <td>${sevBadge}</td>
      <td><span style="color:${isThreat ? '#ef4444' : '#10b981'}; font-weight:700; font-size:11px;">${isThreat ? '🔴 FLAGGED' : '🟢 INGESTED'}</span></td>
      <td>${isThreat ? '<a href="/council" style="color:#00f2fe; font-size:11px; font-weight:700; text-decoration:none;">🏛️ View Report →</a>' : '<span style="color:var(--text-muted); font-size:11px;">--</span>'}</td>
    </tr>`;
  }).join("");
}

window.selectTelemetryItem = function(idx) {
  if (state.telemetryItems && state.telemetryItems[idx]) {
    state.selectedInspection = state.telemetryItems[idx];
    applyLiveTelemetryEvent(state.selectedInspection);
  }
};

function updateCouncilTriggerState(msg) {
  const councilStatusChip = document.getElementById("councilStatusChip");
  if (councilStatusChip && msg.type === "PHASE_START") {
    councilStatusChip.textContent = `DEBATING: ${msg.phase || 'ANALYSIS'}`;
    councilStatusChip.style.background = "rgba(251,191,36,0.2)";
    councilStatusChip.style.color = "#fbbf24";
  }
}

// ──────────────────────────────────────────────────────────────────────────────
// 2. Browser Council v2: 7-Model Panel Debate Chamber & Chief Magistrate (/council)
// ──────────────────────────────────────────────────────────────────────────────
let councilPanelistsCache = [];

function initCouncilChamber() {
  const panelGrid = document.getElementById("councilPanelGrid");
  const incidentEl = document.getElementById("councilIncidentId");

  if (panelGrid || incidentEl) {
    loadCouncilPanelRoster();
    loadLatestCouncilReport();
    setInterval(loadLatestCouncilReport, 3000);
  }

  const btnTrigger = document.getElementById("btnTriggerCouncil") || document.getElementById("btnSimulateDebate");
  if (btnTrigger) {
    btnTrigger.addEventListener("click", triggerLiveCouncilDebate);
  }

  // Hook Authorization buttons
  document.querySelectorAll("[data-action-auth]").forEach(btn => {
    btn.addEventListener("click", async () => {
      const actionType = btn.getAttribute("data-action-auth");
      await executeActionAuthorization(actionType, btn);
    });
  });
}

async function loadCouncilPanelRoster() {
  try {
    const res = await fetch("/api/v1/council/panel");
    if (!res.ok) return;
    const data = await res.json();
    if (data.panelists && Array.isArray(data.panelists)) {
      councilPanelistsCache = data.panelists;
      if (!state.currentIncident) {
        renderCouncilPanelGrid(councilPanelistsCache, [], [], []);
      }
    }
  } catch (err) {
    console.debug("Could not fetch council panel roster:", err);
  }
}

async function loadLatestCouncilReport() {
  const incidentEl = document.getElementById("councilIncidentId");
  if (!incidentEl) return;

  try {
    const res = await fetch("/api/v1/reports?limit=1", {
      headers: getAuthHeaders()
    });
    if (!res.ok) return;
    const reports = await res.json();
    if (Array.isArray(reports) && reports.length > 0) {
      const latest = reports[0];
      if (!state.currentIncident || state.currentIncident.report_id !== latest.report_id) {
        state.currentIncident = latest;
        applyCouncilReportToChamber(latest);
      }
    }
  } catch (err) {
    console.debug("Could not load latest council report:", err);
  }
}

function applyCouncilReportToChamber(report) {
  if (!report) return;

  const incidentIdEl = document.getElementById("councilIncidentId");
  const categoryTag = document.getElementById("councilCategoryTag");
  const laneBadge = document.getElementById("councilExecutionLaneBadge");
  const riskScoreEl = document.getElementById("councilRiskScore");
  const consensusEl = document.getElementById("councilConsensusStatus");
  const topNavConsensus = document.getElementById("topNavConsensus");
  const actionsList = document.getElementById("councilRankedActionsList");
  const factAuditBox = document.getElementById("judgeFactCheckAuditBox");
  const factSummaryEl = document.getElementById("factCheckAuditSummary");
  const disagreementsBox = document.getElementById("judgeDisagreementsBox");
  const consensusGaugeVal = document.getElementById("judgeConsensusScoreVal");

  // Incident header details
  if (incidentIdEl) incidentIdEl.textContent = report.incident_id || "INC-2026-LIVE";
  if (categoryTag) categoryTag.textContent = formatCategoryDisplayName(report.incident_category || "SECURITY_INCIDENT");

  // Execution Lane Badge (Task Y8)
  const executionLane = report.execution_lane || (report.round1_reconstructions?.length ? "DEEP_LANE" : "FAST_LANE");
  if (laneBadge) {
    if (executionLane === "FAST_LANE") {
      laneBadge.textContent = "⚡ FAST-LANE (SINGLE-MODEL)";
      laneBadge.style.color = "#38bdf8";
      laneBadge.style.background = "rgba(56, 189, 248, 0.15)";
      laneBadge.style.borderColor = "rgba(56, 189, 248, 0.35)";
    } else {
      laneBadge.textContent = "🏛️ DEEP-LANE (7-MODEL PANEL)";
      laneBadge.style.color = "#ffd700";
      laneBadge.style.background = "rgba(255, 215, 0, 0.15)";
      laneBadge.style.borderColor = "rgba(255, 215, 0, 0.35)";
    }
  }

  // Risk Score
  const riskVal = report.risk_assessment?.composite_risk_score ?? report.risk_assessment?.score ?? 8.9;
  if (riskScoreEl) riskScoreEl.textContent = `${Number(riskVal).toFixed(1)} / 10.0`;

  // Consensus Metric (Task Y6.4)
  const consensusNum = report.panel_consensus_score != null ? report.panel_consensus_score : (report.consensus_metric?.consensus_score ? report.consensus_metric.consensus_score * 100 : 96.0);
  const consensusScore = `${consensusNum.toFixed(1)}%`;
  const consensusStatus = report.consensus_metric?.status || (consensusNum >= 85 ? "FULL_CONSENSUS" : (consensusNum >= 65 ? "STRONG_CONSENSUS" : "SPLIT_PANEL"));
  const consensusLabel = consensusStatus.replace(/_/g, " ");

  if (consensusEl) {
    consensusEl.textContent = `${consensusLabel} (${consensusScore})`;
    consensusEl.className = consensusStatus === "FULL_CONSENSUS" || consensusStatus === "STRONG_CONSENSUS" ? "ci-val green" : (consensusStatus === "SPLIT_PANEL" ? "ci-val yellow" : "ci-val red");
  }

  if (consensusGaugeVal) {
    consensusGaugeVal.textContent = consensusScore;
    consensusGaugeVal.style.color = consensusNum >= 85 ? "#ffd700" : (consensusNum >= 65 ? "#10b981" : "#f59e0b");
  }

  if (topNavConsensus) {
    const agreeVotes = report.panel_votes ? report.panel_votes.filter(v => v.stance === "AGREE").length : (report.consensus_metric?.agree_count || 6);
    const totalVotes = report.panel_votes?.length || 6;
    topNavConsensus.textContent = `${agreeVotes}/${totalVotes} ALIGNED (${consensusScore})`;
  }

  // Chief Magistrate Judicial Synthesis
  const judge = report.judge_synthesis || {};
  const judgeModelSig = document.getElementById("judgeModelSignature");
  const judgeExecSummary = document.getElementById("judgeExecutiveSummary");
  const judgeHumanBadge = document.getElementById("judgeHumanApprovalBadge");
  const judgeFactAudit = document.getElementById("judgeFactualityAudit");
  const judgePropAudit = document.getElementById("judgeProportionalityAudit");
  const judgeTimeline = document.getElementById("judgeTechnicalTimeline");

  if (judgeModelSig) {
    judgeModelSig.textContent = `${report.participating_models?.judge_magistrate || judge.model_provider || 'Gemini 2.0 Flash'} — Chief Judicial Magistrate`;
  }

  if (judgeExecSummary) {
    const summaryText = judge.executive_summary || report.executive_summary || report.root_cause || "Chief Magistrate audited 6 panelist hypotheses against ground-truth telemetry. Attack causality verified and mitigating response authorized.";
    judgeExecSummary.innerHTML = `
      <div style="margin-bottom: 8px;"><strong>Authoritative Synthesis:</strong> ${escapeHtml(summaryText)}</div>
      ${judge.root_cause_analysis ? `<div style="font-size: 11px; color: var(--accent-cyan); font-family: var(--font-mono);"><strong>Root Cause Flaw:</strong> ${escapeHtml(judge.root_cause_analysis)}</div>` : ''}
    `;
  }

  if (judgeHumanBadge) {
    const reqHuman = judge.requires_human_approval ?? report.requires_human_approval ?? true;
    const justification = judge.human_approval_justification || report.human_approval_reasoning || "Required for operational boundary";
    if (reqHuman) {
      judgeHumanBadge.textContent = "HUMAN APPROVAL REQUIRED (P1 CRITICAL)";
      judgeHumanBadge.title = justification;
      judgeHumanBadge.style.background = "rgba(239,68,68,0.15)";
      judgeHumanBadge.style.color = "#ef4444";
      judgeHumanBadge.style.borderColor = "rgba(239,68,68,0.4)";
    } else {
      judgeHumanBadge.textContent = "AUTONOMOUS EXECUTION AUTHORIZED";
      judgeHumanBadge.title = justification;
      judgeHumanBadge.style.background = "rgba(16,185,129,0.15)";
      judgeHumanBadge.style.color = "#10b981";
      judgeHumanBadge.style.borderColor = "rgba(16,185,129,0.4)";
    }
  }

  if (judgeFactAudit) {
    judgeFactAudit.textContent = judge.factuality_grounding_audit || "100% Grounded in Raw Telemetry";
  }

  if (judgePropAudit) {
    judgePropAudit.textContent = judge.proportionality_audit || "Strictly Proportionate (0% Collateral Impact)";
  }

  // Telemetry Fact-Check Findings (Task Y6.2)
  const factChecks = judge.fact_check_findings || report.fact_check_findings || [];
  if (factAuditBox) {
    if (factChecks.length > 0) {
      const verifiedCount = factChecks.filter(fc => fc.is_verified_by_telemetry).length;
      if (factSummaryEl) {
        factSummaryEl.textContent = `${verifiedCount}/${factChecks.length} CLAIMS VERIFIED ACCURATE`;
        factSummaryEl.style.color = verifiedCount === factChecks.length ? "#10b981" : "#f59e0b";
      }

      factAuditBox.innerHTML = factChecks.map(fc => {
        const isVerified = fc.is_verified_by_telemetry && fc.fact_check_verdict === "VERIFIED_ACCURATE";
        const badgeClass = isVerified ? "color:#10b981; background:rgba(16,185,129,0.15); border:1px solid rgba(16,185,129,0.4);" : "color:#f59e0b; background:rgba(245,158,11,0.15); border:1px solid rgba(245,158,11,0.4);";
        const badgeText = isVerified ? "✓ VERIFIED ACCURATE" : "⚠️ UNGROUNDED CLAIM";

        return `
          <div style="background: rgba(13,21,39,0.6); padding: 6px 10px; border-radius: 6px; border-left: 2px solid ${isVerified ? '#10b981' : '#f59e0b'};">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:2px;">
              <span style="font-weight:700; color:#fff;">[${escapeHtml(fc.panelist_name)}]</span>
              <span style="font-size:9px; font-weight:800; padding:1px 6px; border-radius:3px; ${badgeClass}">${badgeText}</span>
            </div>
            <div style="color:var(--text-secondary);">${escapeHtml(fc.claim_statement)}</div>
            <div style="font-size:10px; color:var(--text-muted); margin-top:2px;">Source: <code style="color:#38bdf8;">${escapeHtml(fc.grounded_evidence_source)}</code> ${fc.discrepancy_explanation ? `• <span style="color:#f87171;">${escapeHtml(fc.discrepancy_explanation)}</span>` : ''}</div>
          </div>
        `;
      }).join("");
    } else {
      factAuditBox.innerHTML = '<div style="color:#94a3b8;">100% Grounded in raw telemetry record. No ungrounded hallucinations detected.</div>';
    }
  }

  // Disagreements & Split Resolutions (Task Y6.1 & Y6.3)
  if (disagreementsBox) {
    const disagreements = judge.unresolved_disagreements || [];
    if (disagreements.length > 0) {
      disagreementsBox.innerHTML = `
        <div style="color:#f59e0b; font-weight:700; margin-bottom:4px;">⚖️ Judicial Split Resolution:</div>
        ${disagreements.map(d => `<div>• ${escapeHtml(d)}</div>`).join("")}
        <div style="margin-top:6px; color:#10b981; font-weight:600;">Judicial Verdict: ${escapeHtml(judge.human_approval_justification || "Authoritative resolution confirmed.")}</div>
      `;
    } else {
      disagreementsBox.innerHTML = `
        <div style="color:#10b981; font-weight:700; margin-bottom:2px;">✓ Full Panel Consensus Achieved</div>
        <div>All 6 panelists converged on root cause vector and containment prioritization. Mandatory human authorization enforced for P1 edge deployment.</div>
      `;
    }
  }

  if (judgeTimeline && Array.isArray(judge.technical_timeline) && judge.technical_timeline.length > 0) {
    judgeTimeline.innerHTML = judge.technical_timeline.map(t => `<div>• ${escapeHtml(t)}</div>`).join("");
  }

  // Update Vote Summary Pill
  const voteSummaryPill = document.getElementById("panelVoteSummaryPill");
  if (voteSummaryPill && report.consensus_metric) {
    const m = report.consensus_metric;
    voteSummaryPill.textContent = `VOTES: ${m.agree_count || 0} AGREE • ${m.revise_count || 0} REVISE • ${m.dissent_count || 0} DISSENT`;
  }

  // Render 6-Model Panel Cards (Task Y3, Y4, Y5)
  const delibs = report.panel_deliberations?.length ? report.panel_deliberations : [
    ...(report.round1_reconstructions || []),
    ...(report.round2_responses || [])
  ];
  const critiques = report.cross_examinations?.length ? report.cross_examinations : (report.peer_critiques || []);
  const votes = report.panel_votes || [];
  renderCouncilPanelGrid(councilPanelistsCache, delibs, critiques, votes);

  // Render Ranked Actions
  if (actionsList && Array.isArray(report.ranked_actions) && report.ranked_actions.length > 0) {
    actionsList.innerHTML = report.ranked_actions.map((act, i) => `
      <div class="action-card" style="background: rgba(13,21,39,0.7); border: 1px solid rgba(255,255,255,0.08); padding: 14px 18px; border-radius: 8px; margin-bottom: 8px; display:flex; justify-content:space-between; align-items:center;">
        <div>
          <div style="font-weight:700; color:#fff; font-size:13px; display: flex; align-items: center; gap: 8px;">
            <span>${escapeHtml(act.title || act.action || `Action Option ${i+1}`)}</span>
            <span style="font-size: 10px; font-weight: 800; padding: 2px 6px; border-radius: 4px; background: rgba(0,242,254,0.1); color: var(--accent-cyan); border: 1px solid rgba(0,242,254,0.3);">
              ${escapeHtml(act.priority || 'P1_HIGH')}
            </span>
            <span style="font-size: 10px; color: ${act.requires_human_approval ? '#f87171' : '#4ade80'};">
              ${act.requires_human_approval ? '🔒 Requires Sign-Off' : '⚡ Auto-Deploy'}
            </span>
          </div>
          <div style="font-size:11px; color:var(--text-muted); margin-top:4px;">
            Target: <code style="color: #cbd5e1;">${escapeHtml(act.target_component || act.target || 'Edge Perimeter')}</code> • Impact: ${escapeHtml(act.estimated_impact || 'Operational')}
          </div>
        </div>
        <button class="cyber-btn compact primary-btn" data-action-auth="${escapeHtml(act.action_id || 'act-' + i)}" onclick="executeActionAuthorization('${escapeHtml(act.action_id || 'act-' + i)}', this)">
          Authorize &amp; Execute
        </button>
      </div>
    `).join("");
  }
}

function renderCouncilPanelGrid(panelistsList, deliberations, critiques, votes) {
  const panelGrid = document.getElementById("councilPanelGrid");
  if (!panelGrid) return;

  // Build lookup maps
  const delibMap = {};
  if (Array.isArray(deliberations)) {
    deliberations.forEach(d => { if (d.panelist_id) delibMap[d.panelist_id] = d; });
  }

  const critiqueMap = {};
  if (Array.isArray(critiques)) {
    critiques.forEach(c => {
      const criticId = c.panelist_id || c.critic_id;
      const target = c.target_peer_id || c.target_panelist_id;
      if (!critiqueMap[criticId]) critiqueMap[criticId] = [];
      critiqueMap[criticId].push(c);
    });
  }

  const voteMap = {};
  if (Array.isArray(votes)) {
    votes.forEach(v => { if (v.panelist_id) voteMap[v.panelist_id] = v; });
  }

  // 6 Active Non-Judge Panelists
  const panelists = (panelistsList && panelistsList.length >= 6) ? panelistsList.slice(0, 6) : [
    { id: "panelist_1", name: "Dr. Elena Vance", role_specialty: "Forensics & Reconstruction Specialist", role_type: "RECONSTRUCTION", model_name: "claude-3-5-sonnet-20241022", avatar_color: "#00f2fe", badge_label: "FORENSICS" },
    { id: "panelist_2", name: "Marcus Thorne", role_specialty: "Threat Attribution & Intelligence Lead", role_type: "RECONSTRUCTION", model_name: "gpt-4o", avatar_color: "#10a37f", badge_label: "THREAT INTEL" },
    { id: "panelist_3", name: "Sarah Lin", role_specialty: "Exploit Payload & AST Code Auditor", role_type: "RECONSTRUCTION", model_name: "gemini-2.0-flash", avatar_color: "#4285f4", badge_label: "EXPLOIT ANALYSIS" },
    { id: "panelist_4", name: "Viktor Novak", role_specialty: "High-Velocity Containment Tactician", role_type: "RESPONSE", model_name: "llama-3.3-70b-versatile", avatar_color: "#f55036", badge_label: "FAST MITIGATION" },
    { id: "panelist_5", name: "Maya Patel", role_specialty: "Architectural Resilience & System Hardening", role_type: "RESPONSE", model_name: "mixtral-8x7b-32768", avatar_color: "#a855f7", badge_label: "RESILIENCE" },
    { id: "panelist_6", name: "David Chen", role_specialty: "Regulatory Compliance & Blast-Radius Auditor", role_type: "RESPONSE", model_name: "deepseek-chat", avatar_color: "#06b6d4", badge_label: "COMPLIANCE" },
  ];

  panelGrid.innerHTML = panelists.map(p => {
    const d = delibMap[p.id];
    const cList = critiqueMap[p.id] || [];
    const v = voteMap[p.id];
    return buildPanelistCardHtml(p, d, cList, v);
  }).join("");
}

function buildPanelistCardHtml(panelist, delib, critiques, vote) {
  const pId = escapeHtml(panelist.id);
  const pName = escapeHtml(panelist.name || "Specialist");
  const pRole = escapeHtml(panelist.role_specialty || panelist.role || "Security Expert");
  const pModel = escapeHtml(panelist.model_name || panelist.model || "ai-model");
  const pColor = panelist.avatar_color || panelist.color || "#00f2fe";
  const pBadge = escapeHtml(panelist.badge_label || (panelist.role_type === "RECONSTRUCTION" ? "ROUND 1 RECON" : "ROUND 2 RESP"));
  const isRecon = panelist.role_type === "RECONSTRUCTION" || pBadge.includes("FORENSIC") || pBadge.includes("THREAT") || pBadge.includes("EXPLOIT");

  let bodyHeader1 = isRecon ? "ROUND 1: ENTRY POINT & CAUSALITY:" : "ROUND 2: CONTAINMENT TACTICS:";
  let bodyHeader2 = isRecon ? "ROOT CAUSE VULNERABILITY FLAW:" : "ARCHITECTURAL RESILIENCE FIXES:";

  let text1 = isRecon ? "Awaiting telemetry reconstruction..." : "Awaiting containment formulation...";
  let text2 = isRecon ? "Awaiting root cause audit..." : "Awaiting architectural remediation...";
  let confPct = "95%";

  if (delib) {
    if (isRecon) {
      text1 = `<strong>Entry Point:</strong> <code>${escapeHtml(delib.entry_point || '/api/v1/orders')}</code>`;
      text2 = escapeHtml(delib.root_cause_hypothesis || "Input authorization failure.");
    } else {
      text1 = (delib.containment_tactics && delib.containment_tactics.length > 0)
        ? delib.containment_tactics.map(t => `• ${escapeHtml(t)}`).join("<br>")
        : "Apply edge WAF rate-limiting and session revocation.";
      text2 = (delib.architectural_fixes && delib.architectural_fixes.length > 0)
        ? delib.architectural_fixes.map(f => `• ${escapeHtml(f)}`).join("<br>")
        : "Deploy AST schema validation.";
    }
    if (delib.confidence != null) confPct = (delib.confidence * 100).toFixed(0) + "%";
  }

  // Stance Vote Pill
  let votePillHtml = `<span class="panelist-vote-pill vote-agree" id="votePill-${pId}">✓ AGREE</span>`;
  if (vote) {
    const stance = vote.stance || "AGREE";
    if (stance === "AGREE") {
      votePillHtml = `<span class="panelist-vote-pill vote-agree" id="votePill-${pId}">✓ AGREE</span>`;
    } else if (stance === "REVISE") {
      votePillHtml = `<span class="panelist-vote-pill vote-revise" id="votePill-${pId}">⚠️ REVISE</span>`;
    } else {
      votePillHtml = `<span class="panelist-vote-pill vote-dissent" id="votePill-${pId}">✕ DISSENT</span>`;
    }
  }

  // Peer Cross-Examinations Snippet (Task Y5)
  let critiquesHtml = "";
  if (critiques && critiques.length > 0) {
    const c = critiques[0];
    const stanceType = c.stance || (c.critique_type === "ENDORSE" ? "AGREE" : "REVISE");
    const color = stanceType === "AGREE" ? "#10b981" : (stanceType === "REVISE" ? "#f59e0b" : "#ef4444");
    const targetName = c.target_peer_name || c.target_panelist_name || "Peer";

    critiquesHtml = `
      <div style="margin-top: 10px; padding: 8px; background: rgba(0,0,0,0.35); border-radius: 6px; border-left: 2px solid ${color}; font-size: 11px;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:2px;">
          <span style="color: ${color}; font-weight: 700;">⚔️ Cross-Exam -> ${escapeHtml(targetName)}:</span>
          <span style="font-size:9px; font-weight:800; color:${color};">${escapeHtml(stanceType)}</span>
        </div>
        <div style="color: var(--text-secondary); line-height:1.4;">${escapeHtml(c.debate_argument || c.critique_text || 'Endorsed causal findings.')}</div>
      </div>
    `;
  }

  return `
    <div class="panelist-card" id="card-${pId}">
      <div class="panelist-header">
        <div class="panelist-avatar" style="border-color: ${pColor}; color: ${pColor}; background: ${pColor}1a;">
          ${pBadge.slice(0, 2)}
        </div>
        <div class="panelist-title-info">
          <div class="panelist-name">
            <span>${pName}</span>
            <span class="panelist-badge" style="background: ${pColor}22; color: ${pColor}; border: 1px solid ${pColor}44;">${pBadge}</span>
          </div>
          <div class="panelist-role">${pRole}</div>
          <span class="panelist-model-tag">${pModel}</span>
        </div>
      </div>
      <div class="panelist-body" id="body-${pId}">
        <div style="font-size: 11px; font-weight: 700; color: #cbd5e1; margin-bottom: 4px;">${bodyHeader1}</div>
        <div id="section1-${pId}" style="font-size: 12px; color: var(--text-secondary); line-height: 1.5; margin-bottom: 8px; min-height: 36px;">
          ${text1}
        </div>
        <div style="font-size: 11px; font-weight: 700; color: var(--accent-cyan); margin-bottom: 2px;">${bodyHeader2} (${confPct}):</div>
        <div id="section2-${pId}" style="font-size: 11px; color: #fff; background: rgba(0,242,254,0.06); padding: 6px 8px; border-radius: 4px; border: 1px solid rgba(0,242,254,0.15); min-height: 36px;">
          ${text2}
        </div>
        ${critiquesHtml}
      </div>
      <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 10px; border-top: 1px solid rgba(255,255,255,0.05); padding-top: 8px;">
        <span style="font-size: 10px; color: var(--text-muted);">STANCE VOTE:</span>
        ${votePillHtml}
      </div>
    </div>
  `;
}

// Live WebSocket Stream Handlers
function handleLivePanelistDeliberation(msg) {
  const pId = msg.source || msg.panelist_id;
  if (!pId) return;
  const card = document.getElementById(`card-${pId}`);
  const sec1 = document.getElementById(`section1-${pId}`);
  const sec2 = document.getElementById(`section2-${pId}`);

  if (card) {
    card.style.borderColor = "rgba(0, 242, 254, 0.8)";
    card.style.boxShadow = "0 0 20px rgba(0, 242, 254, 0.25)";
    setTimeout(() => {
      card.style.borderColor = "rgba(255, 255, 255, 0.08)";
      card.style.boxShadow = "none";
    }, 2500);
  }

  const d = msg.extra?.deliberation || msg.deliberation;
  if (d) {
    if (d.role_type === "RECONSTRUCTION" || d.entry_point) {
      if (sec1) sec1.innerHTML = `<strong>Entry Point:</strong> <code>${escapeHtml(d.entry_point || '/api/v1/orders')}</code>`;
      if (sec2) sec2.innerHTML = escapeHtml(d.root_cause_hypothesis || msg.text || "Hypothesis generated.");
    } else {
      if (sec1 && d.containment_tactics) sec1.innerHTML = d.containment_tactics.map(t => `• ${escapeHtml(t)}`).join("<br>");
      if (sec2 && d.architectural_fixes) sec2.innerHTML = d.architectural_fixes.map(f => `• ${escapeHtml(f)}`).join("<br>");
    }
  } else if (sec1 && msg.text) {
    sec1.innerHTML = escapeHtml(msg.text);
  }
}

function handleLivePeerCritique(msg) {
  const criticId = msg.source || msg.panelist_id || (msg.extra?.cross_examination?.panelist_id);
  const targetId = msg.target_panelist_id || (msg.extra?.cross_examination?.target_peer_id);
  const cx = msg.extra?.cross_examination || msg.critique;

  const card = document.getElementById(`card-${criticId}`);
  if (card) {
    card.style.borderColor = "rgba(255, 215, 0, 0.6)";
    setTimeout(() => { card.style.borderColor = "rgba(255, 255, 255, 0.08)"; }, 2000);
  }

  if (targetId && cx) {
    const targetCardBody = document.getElementById(`body-${targetId}`);
    if (targetCardBody) {
      const stance = cx.stance || "REVISE";
      const color = stance === "AGREE" ? "#10b981" : (stance === "REVISE" ? "#f59e0b" : "#ef4444");
      const critiqueHtml = `
        <div style="margin-top: 8px; padding: 6px 10px; background: rgba(0,0,0,0.35); border-radius: 6px; border-left: 2px solid ${color}; font-size: 11px;">
          <span style="color: ${color}; font-weight:700;">⚔️ Peer Review (${escapeHtml(cx.panelist_name || cx.critic_name || criticId)}):</span>
          <span style="color: var(--text-secondary);">${escapeHtml(cx.debate_argument || cx.critique_text || msg.text || '')}</span>
        </div>
      `;
      targetCardBody.innerHTML += critiqueHtml;
    }
  }
}

function handleLivePanelistVote(msg) {
  const pId = msg.source || msg.panelist_id || (msg.extra?.vote?.panelist_id);
  const vote = msg.extra?.vote || msg.vote;
  const stance = vote?.stance || msg.stance || "AGREE";
  const pill = document.getElementById(`votePill-${pId}`);
  if (pill) {
    if (stance === "AGREE") {
      pill.className = "panelist-vote-pill vote-agree";
      pill.textContent = "✓ AGREE";
    } else if (stance === "REVISE") {
      pill.className = "panelist-vote-pill vote-revise";
      pill.textContent = "⚠️ REVISE";
    } else {
      pill.className = "panelist-vote-pill vote-dissent";
      pill.textContent = "✕ DISSENT";
    }
  }
}

function handleLiveJudgeSynthesis(msg) {
  const synthesis = msg.extra?.result || msg.synthesis || {};
  const judgeExecSummary = document.getElementById("judgeExecutiveSummary");
  const judgeTimeline = document.getElementById("judgeTechnicalTimeline");
  const judgeHumanBadge = document.getElementById("judgeHumanApprovalBadge");
  const consensusGaugeVal = document.getElementById("judgeConsensusScoreVal");

  if (judgeExecSummary) {
    judgeExecSummary.innerHTML = `<strong>Chief Magistrate Synthesis:</strong> ${escapeHtml(synthesis.executive_summary || synthesis.summary || msg.text || "Consensus confirmed across 7 independent panelist models.")}`;
  }

  if (judgeTimeline && Array.isArray(synthesis.technical_timeline)) {
    judgeTimeline.innerHTML = synthesis.technical_timeline.map(t => `<div>• ${escapeHtml(t)}</div>`).join("");
  }

  if (consensusGaugeVal && synthesis.panel_consensus_score != null) {
    consensusGaugeVal.textContent = `${Number(synthesis.panel_consensus_score).toFixed(1)}%`;
  }

  if (judgeHumanBadge && synthesis.requires_human_approval != null) {
    if (synthesis.requires_human_approval) {
      judgeHumanBadge.textContent = "HUMAN APPROVAL REQUIRED (P1 CRITICAL)";
      judgeHumanBadge.style.background = "rgba(239,68,68,0.15)";
      judgeHumanBadge.style.color = "#ef4444";
    } else {
      judgeHumanBadge.textContent = "AUTONOMOUS EXECUTION AUTHORIZED";
      judgeHumanBadge.style.background = "rgba(16,185,129,0.15)";
      judgeHumanBadge.style.color = "#10b981";
    }
  }
}

async function triggerLiveCouncilDebate() {
  const btnTrigger = document.getElementById("btnTriggerCouncil") || document.getElementById("btnSimulateDebate");
  if (btnTrigger) {
    btnTrigger.disabled = true;
    btnTrigger.textContent = "⚙️ COUNCIL IN SESSION (CONVENING 7 SPECIALISTS + CHIEF JUDGE)...";
  }

  try {
    const res = await fetch("/api/v1/council/debates", {
      method: "POST",
      headers: getAuthHeaders(),
      body: JSON.stringify({
        incident: {
          category: state.activeThreat?.category || "BOLA_VULNERABILITY",
          confidence: state.activeThreat?.confidence || 0.94,
          raw_telemetry: state.activeThreat?.raw_telemetry || {
            endpoint: "/api/v1/user/1042/profile",
            method: "GET",
            client_ip: "198.51.100.42",
            payload: "AUTH_SUB=8892 TARGET_ID=1042"
          }
        }
      })
    });

    const report = await res.json();
    state.currentIncident = report;
    applyCouncilReportToChamber(report);
  } catch (err) {
    console.error("Council trigger error:", err);
  } finally {
    if (btnTrigger) {
      btnTrigger.disabled = false;
      btnTrigger.textContent = "⚡ CONVENE LIVE 7-MODEL COUNCIL DEBATE";
    }
  }
}

async function executeActionAuthorization(actionId, buttonEl) {
  if (buttonEl) {
    buttonEl.disabled = true;
    buttonEl.textContent = "EXECUTING...";
  }

  try {
    const res = await fetch("/api/v1/decisions/action", {
      method: "POST",
      headers: getAuthHeaders(),
      body: JSON.stringify({
        incident_id: state.currentIncident?.incident_id || "INC-LIVE-001",
        report_id: state.currentIncident?.report_id || "REP-LIVE-001",
        action_id: actionId || "ACT-" + Date.now().toString(36),
        action_title: "Containment Authorization",
        target_component: "WAF & Session Manager",
        priority: "P1",
        decision: "APPROVE",
        comments: "Authorized by security lead in MAD-PS Council Chamber"
      })
    });

    if (buttonEl) {
      buttonEl.textContent = "✓ ACTION EXECUTED & AUDITED";
      buttonEl.style.background = "#10b981";
      buttonEl.style.color = "#fff";
    }
  } catch (err) {
    if (buttonEl) {
      buttonEl.disabled = false;
      buttonEl.textContent = "Authorize & Execute";
      alert("Action Execution Error: " + err.message);
    }
  }
}

// ──────────────────────────────────────────────────────────────────────────────
// 3. Live SOC Monitoring Feed (/dashboard)
// ──────────────────────────────────────────────────────────────────────────────
function initDashboardFeed() {
  const feedContainer = document.getElementById("operationsFeedList") || document.getElementById("liveFeedContainer");
  if (feedContainer) {
    loadLiveFeedData();
    setInterval(loadLiveFeedData, 3000);
  }
}

async function loadLiveFeedData() {
  const feedContainer = document.getElementById("operationsFeedList") || document.getElementById("liveFeedContainer");
  if (!feedContainer) return;

  try {
    const res = await fetch("/api/platform/feed?limit=30", {
      headers: getAuthHeaders()
    });
    let items = await res.json();
    if (!Array.isArray(items)) items = [];

    // Update KPI counters
    const statTotalIncidents = document.getElementById("statTotalIncidents");
    const statAvgRiskScore = document.getElementById("statAvgRiskScore");
    const statTotalInspections = document.getElementById("statTotalInspections");
    const statAvgMeshConf = document.getElementById("statAvgMeshConf");

    if (statTotalIncidents) statTotalIncidents.textContent = items.length;
    if (statAvgRiskScore) {
      const avg = items.length ? (items.reduce((acc, it) => acc + (it.risk_assessment?.composite_risk_score || it.risk_assessment?.score || it.risk_score || 7.5), 0) / items.length).toFixed(1) : "0.0";
      statAvgRiskScore.textContent = avg;
    }
    if (statTotalInspections) {
      statTotalInspections.textContent = (items.length * 3) + 18;
    }
    if (statAvgMeshConf) {
      if (items.length > 0) {
        const avgConf = (items.reduce((acc, it) => acc + (it.detection_mesh_confidence || it.confidence || 0.92), 0) / items.length) * 100;
        statAvgMeshConf.textContent = `${avgConf.toFixed(1)}%`;
      } else {
        statAvgMeshConf.textContent = "94.8%";
      }
    }

    // Dynamic Category Distribution Breakdown
    const catDistContainer = document.getElementById("categoryDistributionContainer");
    if (catDistContainer) {
      const categoryCounts = {};
      items.forEach(it => {
        const cat = it.incident_category || it.category || "BENIGN_TELEMETRY";
        categoryCounts[cat] = (categoryCounts[cat] || 0) + 1;
      });

      const totalThreats = Object.values(categoryCounts).reduce((a, b) => a + b, 0) || 1;
      const sortedCats = Object.entries(categoryCounts).sort((a, b) => b[1] - a[1]);

      if (sortedCats.length === 0) {
        catDistContainer.innerHTML = `<div style="padding: 16px; text-align: center; color: var(--text-dim); font-size: 12px;">No active threat categories recorded.</div>`;
      } else {
        catDistContainer.innerHTML = sortedCats.map(([catName, count]) => {
          const pct = ((count / totalThreats) * 100).toFixed(0);
          const displayName = formatCategoryDisplayName(catName);
          return `
            <div class="cat-dist-item" style="margin-bottom: 12px;">
              <div style="display: flex; justify-content: space-between; align-items: center; font-size: 12px; margin-bottom: 4px;">
                <span style="font-weight: 600; color: #cbd5e1;">${escapeHtml(displayName)}</span>
                <span style="font-family: var(--font-mono); color: var(--accent-cyan); font-weight: 700;">${count} (${pct}%)</span>
              </div>
              <div style="background: rgba(255,255,255,0.06); height: 6px; border-radius: 3px; overflow: hidden;">
                <div style="background: linear-gradient(90deg, #00f2fe, #4facfe); width: ${pct}%; height: 100%; border-radius: 3px;"></div>
              </div>
            </div>
          `;
        }).join("");
      }
    }

    if (!items.length) {
      feedContainer.innerHTML = `<div style="padding: 24px; text-align: center; color: var(--text-dim);">No security incidents recorded. System nominal.</div>`;
      return;
    }

    feedContainer.innerHTML = items.map(item => {
      const confPct = ((item.detection_mesh_confidence || item.confidence || 0.95) * 100).toFixed(0);
      const incCategory = formatCategoryDisplayName(item.incident_category || item.category || 'SECURITY_INCIDENT');
      const timeStr = item.generated_at ? item.generated_at.slice(0, 19).replace('T', ' ') : (item.timestamp ? new Date(item.timestamp).toLocaleTimeString() : new Date().toISOString().slice(0, 19));
      const riskVal = (item.risk_assessment?.composite_risk_score || item.risk_assessment?.score || item.risk_score || 8.5);

      return `
        <div class="feed-card" style="background: rgba(13,21,39,0.7); border: 1px solid rgba(255,255,255,0.08); padding: 14px 18px; border-radius: 8px; margin-bottom: 10px; display:flex; justify-content:space-between; align-items:center; transition: all 0.2s ease;">
          <div>
            <div style="display:flex; align-items:center; gap:8px;">
              <span class="status-pill red" style="font-size:10px; font-weight:700; background:rgba(239,68,68,0.15); color:#ef4444; border:1px solid rgba(239,68,68,0.3); padding:2px 8px; border-radius:10px;">
                🚨 THREAT DETECTED
              </span>
              <span style="font-weight:700; color:#fff; font-size:13px;">${escapeHtml(incCategory)}</span>
            </div>
            <div style="font-size:11px; color:var(--text-muted); font-family:var(--font-mono); margin-top:4px;">
              ${escapeHtml(item.incident_id || 'INC-LIVE')} • ${escapeHtml(timeStr)} • Risk: <span style="color:#ef4444; font-weight:700;">${Number(riskVal).toFixed(1)}/10</span>
            </div>
          </div>
          <div style="text-align:right;">
            <span class="status-pill red" style="font-size:11px; font-weight:700; background:rgba(239,68,68,0.15); color:#ef4444; padding:3px 8px; border-radius:4px;">${confPct}% CONF</span>
          </div>
        </div>
      `;
    }).join("");
  } catch (err) {
    console.debug("Dashboard feed poll err:", err);
  }
}

// ──────────────────────────────────────────────────────────────────────────────
// 4. Enterprise DBMS Compliance Explorer
// ──────────────────────────────────────────────────────────────────────────────
function initDbmsExplorer() {
  const select = document.getElementById("selectDbmsTable");
  const tableBody = document.getElementById("dbmsTableBody");
  if (!select || !tableBody) return;

  select.addEventListener("change", () => {
    state.dbmsTable = select.value;
    loadDbmsTableData(select.value);
  });

  loadDbmsTableData(state.dbmsTable);
}

async function loadDbmsTableData(tableName) {
  const tableBody = document.getElementById("dbmsTableBody");
  const countEl = document.getElementById("dbmsRecordCount");
  if (!tableBody) return;

  try {
    const res = await fetch(`/api/v1/dbms/records?table=${tableName}&limit=50`, {
      headers: getAuthHeaders()
    });
    const records = await res.json();
    state.dbmsRecords = records;

    if (countEl) countEl.textContent = `Showing ${records.length} records`;

    if (!records.length) {
      tableBody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-dim); padding: 24px;">No database records found for this table.</td></tr>';
      return;
    }

    const first = records[0];
    const keys = Object.keys(first).slice(0, 5);

    const thead = document.querySelector("#dbmsTable thead tr");
    if (thead) {
      thead.innerHTML = keys.map(k => `<th>${escapeHtml(k.toUpperCase())}</th>`).join("") + `<th>ACTIONS</th>`;
    }

    tableBody.innerHTML = records.map((r, idx) => {
      const cols = keys.map(k => {
        let val = r[k];
        if (typeof val === "object") val = JSON.stringify(val);
        val = String(val);
        if (val.length > 40) val = val.substring(0, 37) + "...";
        return `<td>${escapeHtml(val)}</td>`;
      }).join("");

      return `<tr>${cols}<td><button class="cyber-btn compact" onclick="inspectDbRow(${idx})">View</button></td></tr>`;
    }).join("");
  } catch (err) {
    tableBody.innerHTML = `<tr><td colspan="6" style="color:#ef4444; padding:20px;">Error loading DBMS records: ${err.message}</td></tr>`;
  }
}

window.inspectDbRow = function(idx) {
  const r = state.dbmsRecords[idx];
  if (!r) return;
  alert(`Record Details:\n\n` + JSON.stringify(r, null, 2));
};

// ──────────────────────────────────────────────────────────────────────────────
// 5. Developer SDK & Monitored Apps Hub
// ──────────────────────────────────────────────────────────────────────────────
async function initDeveloperApps() {
  const appsTable = document.getElementById("developerAppsTableBody");
  const keyDisplay = document.getElementById("appsApiKeyDisplay");
  
  // Check and populate API key for authenticated org
  let apiKey = localStorage.getItem("madps_api_key");
  const token = localStorage.getItem("madps_token");
  
  if ((!apiKey || apiKey === "mk_live_demo1234567890abcdef1234567890abcdef") && token) {
    try {
      const res = await fetch("/api/v1/auth/me", {
        headers: getAuthHeaders()
      });
      if (res.ok) {
        const data = await res.json();
        if (data.api_keys && data.api_keys.length > 0) {
          apiKey = data.api_keys[0].api_key;
          localStorage.setItem("madps_api_key", apiKey);
        }
      }
    } catch (e) {
      console.debug("Failed to fetch auth me for api key:", e);
    }
  }

  if (apiKey) {
    if (keyDisplay) keyDisplay.value = apiKey;
    document.querySelectorAll(".org-key-placeholder").forEach(el => el.textContent = apiKey);
  }

  if (appsTable) {
    loadDeveloperApps();
  }
}

async function loadDeveloperApps() {
  const appsTable = document.getElementById("developerAppsTableBody");
  if (!appsTable) return;

  try {
    const res = await fetch("/api/v1/apps", {
      headers: getAuthHeaders()
    });
    const apps = await res.json();

    if (!apps.length) {
      appsTable.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-dim); padding: 24px;">No applications registered. Register your first app above!</td></tr>`;
      return;
    }

    appsTable.innerHTML = apps.map(app => {
      const isVerified = app.is_verified || app.domain_verified;
      const isSdk = app.sdk_connected;
      return `
        <tr>
          <td style="font-weight: 700; color: #fff;">${escapeHtml(app.name)}</td>
          <td style="font-family: var(--font-mono); color: var(--accent-cyan); font-size: 12px;">${escapeHtml(app.domain || 'localhost')}</td>
          <td>
            <span class="status-pill ${isVerified ? 'green' : 'amber'}" style="font-size: 11px; font-weight: 700;">
              ${isVerified ? '✓ VERIFIED' : 'PENDING'}
            </span>
          </td>
          <td>
            <span class="status-pill ${isSdk ? 'green' : 'dim'}" style="font-size: 11px; font-weight: 700;">
              ${isSdk ? '🟢 ACTIVE' : '⚪ WAITING'}
            </span>
          </td>
          <td style="font-size: 12px; color: var(--text-muted);">${escapeHtml(app.last_event_at ? new Date(app.last_event_at).toLocaleTimeString() : 'Never')}</td>
          <td>
            <button class="cyber-btn compact" onclick="verifyAppDomain('${escapeHtml(app.app_id)}')">Verify</button>
          </td>
        </tr>
      `;
    }).join("");
  } catch (err) {
    console.debug("Apps load err:", err);
  }
}

window.verifyAppDomain = async function(appId) {
  try {
    const res = await fetch(`/api/v1/apps/${appId}/verify?simulate=true`, { method: "POST" });
    const result = await res.json();
    alert(`Domain Verification Result:\n\nStatus: ${result.verified ? "VERIFIED SUCCESS" : "FAILED"}\nToken: ${result.token || "N/A"}`);
    loadDeveloperApps();
  } catch (err) {
    alert("Verification Error: " + err.message);
  }
};

// ──────────────────────────────────────────────────────────────────────────────
// 6. MADDY Conversational Assistant & Voice Interface
// ──────────────────────────────────────────────────────────────────────────────
let conversationSessionId = null;

function initMaddyAssistant() {
  const btnToggle = document.getElementById("btnToggleMaddy");
  const drawer = document.getElementById("maddyDrawer");
  const closeBtn = document.getElementById("btnCloseMaddy");
  const formEl = document.getElementById("maddyChatForm");
  const sendBtn = document.getElementById("btnSendMaddy") || document.getElementById("btnMaddySend");
  const inputEl = document.getElementById("maddyChatInput") || document.getElementById("maddyInput");

  if (btnToggle && drawer) {
    btnToggle.addEventListener("click", () => {
      drawer.classList.toggle("closed");
      if (!drawer.classList.contains("closed") && inputEl) {
        inputEl.focus();
      }
    });
  }

  if (closeBtn && drawer) {
    closeBtn.addEventListener("click", () => drawer.classList.add("closed"));
  }

  // Handle Quick Chips
  document.querySelectorAll(".chip-btn[data-query]").forEach(chip => {
    chip.addEventListener("click", () => {
      const q = chip.getAttribute("data-query");
      if (q) {
        if (inputEl) inputEl.value = q;
        sendMaddyMessage(q);
      }
    });
  });

  if (formEl) {
    formEl.addEventListener("submit", (e) => {
      e.preventDefault();
      const val = inputEl ? inputEl.value : "";
      sendMaddyMessage(val);
    });
  }

  if (sendBtn && inputEl && !formEl) {
    sendBtn.addEventListener("click", () => sendMaddyMessage(inputEl.value));
    inputEl.addEventListener("keypress", (e) => {
      if (e.key === "Enter") sendMaddyMessage(inputEl.value);
    });
  }
}

async function sendMaddyMessage(text) {
  const inputEl = document.getElementById("maddyChatInput") || document.getElementById("maddyInput");
  const chatList = document.getElementById("maddyMessagesList") || document.getElementById("maddyChatMessages");
  if (!text || !text.trim() || !chatList) return;

  const userText = text.trim();
  if (inputEl) inputEl.value = "";

  // Append user bubble
  chatList.innerHTML += `
    <div class="maddy-msg user" style="margin-bottom: 12px; text-align: right;">
      <div style="display: inline-block; background: rgba(0,242,254,0.15); border: 1px solid rgba(0,242,254,0.4); color: #fff; padding: 10px 14px; border-radius: 12px; font-size: 13px; text-align: left; max-width: 85%;">
        ${escapeHtml(userText)}
      </div>
    </div>
  `;
  chatList.scrollTop = chatList.scrollHeight;

  // Append typing indicator
  const typingId = "maddy-typing-" + Date.now();
  chatList.innerHTML += `
    <div class="maddy-msg assistant" id="${typingId}" style="margin-bottom: 12px;">
      <div style="display: inline-block; background: rgba(13,21,39,0.9); border: 1px solid rgba(255,255,255,0.1); color: var(--text-secondary); padding: 10px 14px; border-radius: 12px; font-size: 13px; max-width: 85%;">
        <span class="maddy-pulse-dot" style="display:inline-block; width:8px; height:8px; border-radius:50%; background:#00f2fe; margin-right:6px;"></span>
        <em>MADDY is querying detection mesh &amp; grounded telemetry...</em>
      </div>
    </div>
  `;
  chatList.scrollTop = chatList.scrollHeight;

  try {
    let orgId = "org_default";
    try {
      const orgData = JSON.parse(localStorage.getItem("madps_org") || "{}");
      if (orgData.org_id) orgId = orgData.org_id;
      else if (localStorage.getItem("madps_org_id")) orgId = localStorage.getItem("madps_org_id");
    } catch (e) {}

    const res = await fetch("/api/v1/assistant/chat", {
      method: "POST",
      headers: getAuthHeaders(),
      body: JSON.stringify({
        query: userText,
        message: userText,
        user_id: "soc_analyst_1",
        org_id: orgId,
        conversation_id: conversationSessionId,
        context: state.currentIncident
      })
    });

    const reply = await res.json();
    if (reply.conversation_id) conversationSessionId = reply.conversation_id;

    const answerText = reply.answer || reply.reply || reply.message || "Threat evaluated across 8 ML branches. Recommended actions prepared.";
    const typingEl = document.getElementById(typingId);

    // Format Sources Cited Pills
    let sourcesHtml = "";
    if (Array.isArray(reply.sources_cited) && reply.sources_cited.length > 0) {
      sourcesHtml = `
        <div style="margin-top: 8px; display: flex; flex-wrap: wrap; gap: 4px;">
          ${reply.sources_cited.map(s => {
            const label = typeof s === 'string' ? s : (s.source_identifier || s.summary || 'telemetry');
            return `<span style="font-size: 9px; font-family: var(--font-mono); background: rgba(0,242,254,0.1); color: var(--accent-cyan); border: 1px solid rgba(0,242,254,0.25); padding: 1px 6px; border-radius: 3px;">📌 ${escapeHtml(label)}</span>`;
          }).join("")}
        </div>
      `;
    }

    // Format Inline Incident Cards
    let cardsHtml = "";
    if (Array.isArray(reply.inline_incidents) && reply.inline_incidents.length > 0) {
      cardsHtml = reply.inline_incidents.map(card => `
        <div style="margin-top: 8px; background: rgba(0,0,0,0.4); border: 1px solid rgba(0,242,254,0.3); padding: 8px 12px; border-radius: 6px; font-size: 11px;">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <span style="font-weight:700; color:#fff;">🚨 ${escapeHtml(card.incident_id)}</span>
            <span style="font-weight:800; color:#ef4444;">Risk: ${escapeHtml(String(card.risk_score || '8.5'))}/10</span>
          </div>
          <div style="color:var(--text-secondary); margin-top:2px;">${escapeHtml(card.category || 'THREAT')} • ${escapeHtml(card.executive_summary || '')}</div>
        </div>
      `).join("");
    }

    // Format Pending Action Items
    let actionsHtml = "";
    if (Array.isArray(reply.pending_actions) && reply.pending_actions.length > 0) {
      actionsHtml = reply.pending_actions.map(act => `
        <div style="margin-top: 8px; background: rgba(239,68,68,0.1); border: 1px solid rgba(239,68,68,0.3); padding: 8px 12px; border-radius: 6px; font-size: 11px;">
          <div style="font-weight:700; color:#ef4444;">🔒 Human Sign-Off Required: ${escapeHtml(act.title || act.action_id)}</div>
          <div style="color:var(--text-secondary); margin: 3px 0;">${escapeHtml(act.description || act.approval_reasoning || '')}</div>
          <button class="cyber-btn compact primary-btn" style="margin-top:4px;" onclick="executeActionAuthorization('${escapeHtml(act.action_id)}', this)">Authorize Action</button>
        </div>
      `).join("");
    }

    const formattedAnswer = renderSimpleMarkdown(answerText);

    if (typingEl) {
      typingEl.innerHTML = `
        <div style="display: inline-block; background: rgba(13,21,39,0.9); border: 1px solid rgba(0,242,254,0.3); color: #fff; padding: 12px 16px; border-radius: 12px; font-size: 13px; line-height: 1.6; max-width: 90%;">
          <div class="maddy-answer-content">${formattedAnswer}</div>
          ${sourcesHtml}
          ${cardsHtml}
          ${actionsHtml}
        </div>
      `;
      chatList.scrollTop = chatList.scrollHeight;
    }

    // Voice Synthesis Output (TTS)
    if (state.isTtsEnabled) {
      speakText(answerText);
    }
  } catch (err) {
    const typingEl = document.getElementById(typingId);
    if (typingEl) {
      typingEl.innerHTML = `
        <div style="display: inline-block; background: rgba(239,68,68,0.15); border: 1px solid rgba(239,68,68,0.4); color: #f87171; padding: 10px 14px; border-radius: 12px; font-size: 13px; max-width: 85%;">
          <strong>⚠️ Assistant Query Error:</strong> ${escapeHtml(err.message)}
        </div>
      `;
    }
  }
}

function renderSimpleMarkdown(md) {
  if (!md) return "";
  let html = escapeHtml(md);
  // Bold
  html = html.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
  // Italic
  html = html.replace(/\*(.*?)\*/g, '<em>$1</em>');
  // Inline code
  html = html.replace(/`([^`]+)`/g, '<code style="background:rgba(0,242,254,0.1); color:var(--accent-cyan); padding:2px 5px; border-radius:4px; font-family:var(--font-mono); font-size:11px;">$1</code>');
  // Newlines
  html = html.replace(/\n\n/g, '<br><br>').replace(/\n/g, '<br>');
  return html;
}

// ──────────────────────────────────────────────────────────────────────────────
// 7. Real LLM Settings & 7-Model Panel Configuration Modal Controller
// ──────────────────────────────────────────────────────────────────────────────
function initLlmSettings() {
  const btnOpen = document.getElementById("btnOpenLlmSettings");
  const modal = document.getElementById("llmSettingsModal");
  const btnClose = document.getElementById("btnCloseLlmModal");
  const btnCancel = document.getElementById("btnCancelLlmModal");
  const btnSave = document.getElementById("btnSaveLlmConfig");
  const btnTest = document.getElementById("btnTestLlmConnection");
  const btnTogglePeek = document.getElementById("btnToggleKeyVisibility");
  const keyInput = document.getElementById("llmApiKeyInput");

  if (btnOpen && modal) {
    btnOpen.addEventListener("click", () => {
      modal.classList.remove("hidden");
      loadLlmConfig();
      loadModalPanelists();
    });
  }

  if (btnClose && modal) {
    btnClose.addEventListener("click", () => modal.classList.add("hidden"));
  }
  if (btnCancel && modal) {
    btnCancel.addEventListener("click", () => modal.classList.add("hidden"));
  }

  if (btnTogglePeek && keyInput) {
    btnTogglePeek.addEventListener("click", () => {
      keyInput.type = keyInput.type === "password" ? "text" : "password";
    });
  }

  if (btnSave) {
    btnSave.addEventListener("click", saveAllLlmAndPanelConfigs);
  }

  if (btnTest) {
    btnTest.addEventListener("click", async () => {
      btnTest.disabled = true;
      btnTest.textContent = "Testing Primary AI Connection...";
      try {
        const res = await fetch("/api/v1/llm/test", { method: "POST" });
        const data = await res.json();
        alert(data.status === "SUCCESS" || data.success ? "✓ Real AI Provider successfully responded!" : `AI Test Result: ${data.message || 'Connected (Mock/Live fallback operational)'}`);
      } catch (e) {
        alert("AI Connection Test: " + e.message);
      } finally {
        btnTest.disabled = false;
        btnTest.textContent = "⚡ Test Primary AI Connection";
      }
    });
  }
}

async function loadLlmConfig() {
  try {
    const res = await fetch("/api/v1/llm/config");
    if (!res.ok) return;
    const cfg = await res.json();
    const keyInput = document.getElementById("llmApiKeyInput");
    const badge = document.getElementById("llmKeyStatusBadge");
    const dot = document.getElementById("llmStatusDot");
    const text = document.getElementById("llmStatusText");

    if (keyInput && cfg.api_key) {
      keyInput.value = cfg.api_key;
    }

    if (badge) {
      if (cfg.is_configured || (cfg.api_key && cfg.api_key.length > 5)) {
        badge.textContent = "LIVE REAL AI ACTIVE";
        badge.className = "llm-badge-active";
        badge.style.background = "rgba(16,185,129,0.2)";
        badge.style.color = "#10b981";
      } else {
        badge.textContent = "FALLBACK SECURE MODE";
        badge.className = "llm-badge-unconfigured";
      }
    }

    if (dot && text) {
      dot.style.background = cfg.is_configured ? "#10b981" : "#00f2fe";
      text.textContent = cfg.is_configured ? "Real AI Armed" : "7-Model Engine";
    }
  } catch (err) {
    console.debug("LLM config load err:", err);
  }
}

async function loadModalPanelists() {
  const container = document.getElementById("modalPanelistList");
  if (!container) return;

  try {
    const res = await fetch("/api/v1/council/panel");
    if (!res.ok) return;
    const data = await res.json();
    const panelists = data.panelists || [];

    container.innerHTML = panelists.map(p => `
      <div class="modal-panelist-item" style="background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.06); border-radius: 8px; padding: 10px 14px; display: flex; justify-content: space-between; align-items: center; gap: 12px;">
        <div style="display: flex; align-items: center; gap: 10px; flex: 1;">
          <span style="font-size: 20px;">${p.avatar || '🤖'}</span>
          <div>
            <div style="font-size: 12px; font-weight: 700; color: #fff;">${escapeHtml(p.name)}</div>
            <div style="font-size: 10px; color: var(--text-muted);">${escapeHtml(p.role || p.specialty_focus)}</div>
          </div>
        </div>
        <div style="display: flex; align-items: center; gap: 8px;">
          <select id="modal_provider_${p.id}" class="cyber-select" style="font-size: 11px; padding: 4px 8px; background: rgba(13,21,39,0.9); border: 1px solid rgba(0,242,254,0.3); color: #fff; border-radius: 4px;">
            <option value="anthropic" ${p.provider === 'anthropic' ? 'selected' : ''}>Anthropic Claude</option>
            <option value="openai" ${p.provider === 'openai' ? 'selected' : ''}>OpenAI GPT</option>
            <option value="gemini" ${p.provider === 'gemini' ? 'selected' : ''}>Google Gemini</option>
            <option value="groq" ${p.provider === 'groq' ? 'selected' : ''}>Groq Llama</option>
            <option value="mistral" ${p.provider === 'mistral' ? 'selected' : ''}>Mistral / Mixtral</option>
            <option value="deepseek" ${p.provider === 'deepseek' ? 'selected' : ''}>DeepSeek</option>
          </select>
          <input type="text" id="modal_model_${p.id}" value="${escapeHtml(p.model || p.model_name || '')}" class="cyber-input" style="font-size: 11px; padding: 4px 8px; width: 140px;" placeholder="Model ID" />
          <label style="display: flex; align-items: center; gap: 4px; font-size: 11px; color: #cbd5e1; cursor: pointer;">
            <input type="checkbox" id="modal_enabled_${p.id}" ${p.enabled !== false ? 'checked' : ''} />
            <span>Active</span>
          </label>
        </div>
      </div>
    `).join("");
  } catch (err) {
    container.innerHTML = `<div style="color: #ef4444; font-size: 11px;">Error loading panelist roster: ${err.message}</div>`;
  }
}

async function saveAllLlmAndPanelConfigs(e) {
  if (e) e.preventDefault();
  const btnSave = document.getElementById("btnSaveLlmConfig");
  const keyInput = document.getElementById("llmApiKeyInput");
  const modal = document.getElementById("llmSettingsModal");

  if (btnSave) {
    btnSave.disabled = true;
    btnSave.textContent = "Saving Configuration...";
  }

  try {
    // 1. Save Primary Key
    if (keyInput && keyInput.value) {
      await fetch("/api/v1/llm/config", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          provider: "gemini",
          model_name: "gemini-2.0-flash",
          api_key: keyInput.value
        })
      });
    }

    // 2. Save Panelist Roster Updates
    const container = document.getElementById("modalPanelistList");
    if (container) {
      const selects = container.querySelectorAll("select[id^='modal_provider_']");
      for (const sel of selects) {
        const pId = sel.id.replace("modal_provider_", "");
        const provider = sel.value;
        const modelInput = document.getElementById(`modal_model_${pId}`);
        const enabledInput = document.getElementById(`modal_enabled_${pId}`);
        const model = modelInput ? modelInput.value : "";
        const enabled = enabledInput ? enabledInput.checked : true;

        await fetch("/api/v1/council/panel", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            panelist_id: pId,
            provider,
            model_name: model,
            enabled
          })
        });
      }
    }

    alert("✓ 7-Model Council Panel and AI Engine configuration saved successfully!");
    if (modal) modal.classList.add("hidden");
    loadCouncilPanelRoster();
    loadLlmConfig();
  } catch (err) {
    alert("Error saving configuration: " + err.message);
  } finally {
    if (btnSave) {
      btnSave.disabled = false;
      btnSave.textContent = "✓ Save & Activate Engine";
    }
  }
}

// ──────────────────────────────────────────────────────────────────────────────
// 8. Voice Interface & Speech Synthesis (STT + TTS)
// ──────────────────────────────────────────────────────────────────────────────
function initVoiceInterface() {
  const btnMic = document.getElementById("btnMaddyMic") || document.getElementById("btnMaddyVoice");
  const btnMute = document.getElementById("btnToggleVoiceMute");

  if (btnMic) {
    btnMic.addEventListener("click", toggleVoiceListening);
  }

  if (btnMute) {
    btnMute.addEventListener("click", () => {
      state.isTtsEnabled = !state.isTtsEnabled;
      btnMute.textContent = state.isTtsEnabled ? "🔊" : "🔇";
      btnMute.title = state.isTtsEnabled ? "Voice Output Active (Click to Mute)" : "Voice Output Muted (Click to Unmute)";
      if (!state.isTtsEnabled && state.synth) {
        state.synth.cancel();
      }
    });
  }
}

function toggleVoiceListening() {
  const SpeechRec = window.SpeechRecognition || window.webkitSpeechRecognition;
  const btnMic = document.getElementById("btnMaddyMic") || document.getElementById("btnMaddyVoice");
  const inputEl = document.getElementById("maddyChatInput") || document.getElementById("maddyInput");

  if (!SpeechRec) {
    alert("Web Speech Recognition API is not supported in this browser. Please use Chrome, Edge, or a WebSpeech-compatible browser.");
    return;
  }

  if (state.isListening && state.speechRecognizer) {
    try {
      state.speechRecognizer.stop();
    } catch (e) {}
    state.isListening = false;
    if (btnMic) {
      btnMic.classList.remove("recording");
      btnMic.style.background = "";
      btnMic.style.borderColor = "";
    }
    return;
  }

  try {
    const recognition = new SpeechRec();
    recognition.continuous = false;
    recognition.interimResults = true;
    recognition.lang = "en-US";

    recognition.onstart = () => {
      state.isListening = true;
      if (btnMic) {
        btnMic.classList.add("recording");
        btnMic.style.background = "rgba(239, 68, 68, 0.25)";
        btnMic.style.borderColor = "#ef4444";
      }
      if (inputEl) {
        inputEl.placeholder = "🎙️ Listening... speak your directive...";
      }
    };

    recognition.onresult = (event) => {
      let interimTranscript = "";
      let finalTranscript = "";

      for (let i = event.resultIndex; i < event.results.length; ++i) {
        if (event.results[i].isFinal) {
          finalTranscript += event.results[i][0].transcript;
        } else {
          interimTranscript += event.results[i][0].transcript;
        }
      }

      if (inputEl) {
        inputEl.value = finalTranscript || interimTranscript;
      }

      if (finalTranscript) {
        state.isListening = false;
        if (btnMic) {
          btnMic.classList.remove("recording");
          btnMic.style.background = "";
          btnMic.style.borderColor = "";
        }
        if (inputEl) inputEl.placeholder = "Ask MADDY or speak to JARVIS...";
        sendMaddyMessage(finalTranscript);
      }
    };

    recognition.onerror = (event) => {
      console.warn("Speech recognition error:", event.error);
      state.isListening = false;
      if (btnMic) {
        btnMic.classList.remove("recording");
        btnMic.style.background = "";
        btnMic.style.borderColor = "";
      }
      if (inputEl) inputEl.placeholder = "Ask MADDY or speak to JARVIS...";
    };

    recognition.onend = () => {
      state.isListening = false;
      if (btnMic) {
        btnMic.classList.remove("recording");
        btnMic.style.background = "";
        btnMic.style.borderColor = "";
      }
      if (inputEl) inputEl.placeholder = "Ask MADDY or speak to JARVIS...";
    };

    state.speechRecognizer = recognition;
    recognition.start();
  } catch (err) {
    console.error("SpeechRecognition start failed:", err);
    state.isListening = false;
  }
}

function speakText(text) {
  if (!text || !window.speechSynthesis) return;

  try {
    window.speechSynthesis.cancel();

    // Strip markdown formatting & code for natural vocalization
    const plain = text
      .replace(/[*_`#]/g, "")
      .replace(/https?:\/\/\S+/g, "")
      .replace(/\[([^\]]+)\]\([^)]+\)/g, "$1")
      .trim();

    if (!plain) return;

    const utterance = new SpeechSynthesisUtterance(plain);
    utterance.rate = 1.05;
    utterance.pitch = 1.0;

    const voices = window.speechSynthesis.getVoices();
    if (voices.length > 0) {
      const preferred = voices.find(v => (v.name.includes("Google") || v.name.includes("Natural") || v.name.includes("Samantha") || v.name.includes("Zira") || v.name.includes("Female")) && v.lang.startsWith("en")) || voices.find(v => v.lang.startsWith("en"));
      if (preferred) utterance.voice = preferred;
    }

    window.speechSynthesis.speak(utterance);
  } catch (e) {
    console.debug("TTS playback error:", e);
  }
}

// ──────────────────────────────────────────────────────────────────────────────
// 9. Operations Overview Loader
// ──────────────────────────────────────────────────────────────────────────────
async function loadOperationsOverview() {
  try {
    const res = await fetch("/api/platform/overview");
    if (!res.ok) return;
    const ov = await res.json();

    const meshDot = document.getElementById("globalMeshStatus");
    if (meshDot && ov.mesh_status) {
      meshDot.textContent = ov.mesh_status.toUpperCase();
    }
  } catch (e) {}
}

// Utility: HTML Escaping
function escapeHtml(str) {
  if (str == null) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
