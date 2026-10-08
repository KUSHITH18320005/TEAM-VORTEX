const { parentPort, workerData } = require("worker_threads");
const crypto = require("crypto");

// Category metadata catalog for enrichment
const CATEGORY_ENRICHMENT = {
  // Phase 1: Web & App (7)
  "nosql-injection": { displayName: "NoSQL Operator Injection", severity: "HIGH", layer: "application", phase: "app", phaseNumber: 1 },
  "xss-stored": { displayName: "Stored Cross-Site Scripting (XSS)", severity: "HIGH", layer: "application", phase: "app", phaseNumber: 1 },
  "open-redirect": { displayName: "Unvalidated URL Redirection", severity: "MEDIUM", layer: "application", phase: "app", phaseNumber: 1 },
  "business-logic": { displayName: "Business Logic / Price Tampering", severity: "MEDIUM", layer: "application", phase: "app", phaseNumber: 1 },
  "api-abuse": { displayName: "API Abuse / Unbounded Collection", severity: "LOW", layer: "application", phase: "app", phaseNumber: 1 },
  "no-rate-limit": { displayName: "Missing Rate Limiting Burst", severity: "LOW", layer: "application", phase: "app", phaseNumber: 1 },
  "data-exfil": { displayName: "Broken Access Control & Exfiltration", severity: "CRITICAL", layer: "application", phase: "app", phaseNumber: 1 },

  // Phase 2: Auth & Identity (12)
  "jwt-abuse": { displayName: "JWT None-Algorithm / Key Forgery", severity: "CRITICAL", layer: "authentication", phase: "auth", phaseNumber: 2 },
  "session-hijack": { displayName: "Session Hijacking (LocalStorage Leak)", severity: "HIGH", layer: "authentication", phase: "auth", phaseNumber: 2 },
  "session-fixation": { displayName: "Session Fixation via Stale Cookie", severity: "LOW", layer: "authentication", phase: "auth", phaseNumber: 2 },
  "bruteforce": { displayName: "High-Frequency Credential Bruteforce", severity: "MEDIUM", layer: "authentication", phase: "auth", phaseNumber: 2 },
  "credential-stuffing": { displayName: "Distributed Credential Stuffing", severity: "MEDIUM", layer: "authentication", phase: "auth", phaseNumber: 2 },
  "password-spraying": { displayName: "Horizontal Password Spraying", severity: "MEDIUM", layer: "authentication", phase: "auth", phaseNumber: 2 },
  "account-takeover": { displayName: "Low-Entropy Password Reset Takeover", severity: "CRITICAL", layer: "authentication", phase: "auth", phaseNumber: 2 },
  "idor": { displayName: "Insecure Direct Object Reference (IDOR)", severity: "HIGH", layer: "authentication", phase: "auth", phaseNumber: 2 },
  "auth-bypass": { displayName: "Role Header Escalation (x-is-admin)", severity: "CRITICAL", layer: "authentication", phase: "auth", phaseNumber: 2 },
  "csrf": { displayName: "Cross-Site Request Forgery (CSRF)", severity: "MEDIUM", layer: "authentication", phase: "auth", phaseNumber: 2 },
  "ssrf": { displayName: "Server-Side Request Forgery (SSRF)", severity: "HIGH", layer: "authentication", phase: "auth", phaseNumber: 2 },
  "xxe": { displayName: "XML External Entity Injection (XXE)", severity: "HIGH", layer: "authentication", phase: "auth", phaseNumber: 2 },

  // Phase 3 & Dataset Replay (19)
  "port-scanning-recon": { displayName: "Port Scanning & Host Discovery", severity: "MEDIUM", layer: "network", phase: "replay", phaseNumber: 3 },
  "network-service-enumeration": { displayName: "Network Service Enumeration", severity: "MEDIUM", layer: "network", phase: "replay", phaseNumber: 3 },
  "dos": { displayName: "Denial of Service (DoS)", severity: "MEDIUM", layer: "network", phase: "replay", phaseNumber: 3 },
  "ddos": { displayName: "Distributed Denial of Service (DDoS)", severity: "HIGH", layer: "network", phase: "replay", phaseNumber: 3 },
  "dns-spoofing": { displayName: "DNS Cache Poisoning / Spoofing", severity: "MEDIUM", layer: "network", phase: "replay", phaseNumber: 3 },
  "mitm": { displayName: "Man-in-the-Middle (ARP Poisoning)", severity: "MEDIUM", layer: "network", phase: "replay", phaseNumber: 3 },
  "ransomware-behavioral": { displayName: "Ransomware File Encryption Burst", severity: "CRITICAL", layer: "malware-behavioral", phase: "replay", phaseNumber: 3 },
  "trojan-behavioral": { displayName: "Trojan Backdoor Infiltration", severity: "MEDIUM", layer: "malware-behavioral", phase: "replay", phaseNumber: 3 },
  "spyware-behavioral": { displayName: "Spyware Covert Exfiltration", severity: "MEDIUM", layer: "malware-behavioral", phase: "replay", phaseNumber: 3 },
  "botnet-c2": { displayName: "Botnet C2 Periodic Beaconing", severity: "HIGH", layer: "malware-behavioral", phase: "replay", phaseNumber: 3 },
  "compromised-iot": { displayName: "Compromised Edge IoT Telemetry", severity: "CRITICAL", layer: "iot", phase: "replay", phaseNumber: 3 },
  "polymorphic-malware": { displayName: "Polymorphic Self-Mutating Malware", severity: "HIGH", layer: "malware-behavioral", phase: "replay", phaseNumber: 3 },
  "apt-stealth-intrusion": { displayName: "Advanced Persistent Threat (APT)", severity: "CRITICAL", layer: "network", phase: "replay", phaseNumber: 3 },
  "encrypted-c2": { displayName: "Encrypted Command-and-Control (TLS)", severity: "HIGH", layer: "malware-behavioral", phase: "replay", phaseNumber: 3 },
  "ai-adaptive": { displayName: "AI-Adaptive / Evasive Perturbation", severity: "HIGH", layer: "research-scenario", phase: "replay", phaseNumber: 3 },
  "supply-chain-compromise": { displayName: "Supply-Chain Dependency Poisoning", severity: "HIGH", layer: "research-scenario", phase: "replay", phaseNumber: 3 },
  "double-extortion": { displayName: "Double Extortion Ransomware", severity: "CRITICAL", layer: "research-scenario", phase: "replay", phaseNumber: 3 },
  "zero-day-eval": { displayName: "Zero-Day Novel Vector Evaluation", severity: "INFO", layer: "research-scenario", phase: "replay", phaseNumber: 3 },
};

// In-Memory Fast LRU Cache for deduplication within the worker
class LRUCache {
  constructor(maxSize = 20000, ttlMs = 10000) {
    this.maxSize = maxSize;
    this.ttlMs = ttlMs;
    this.cache = new Map();
  }

  has(key) {
    const entry = this.cache.get(key);
    if (!entry) return false;
    if (Date.now() - entry.ts > this.ttlMs) {
      this.cache.delete(key);
      return false;
    }
    return true;
  }

  set(key) {
    if (this.cache.size >= this.maxSize) {
      // Evict oldest entry
      const firstKey = this.cache.keys().next().value;
      if (firstKey) this.cache.delete(firstKey);
    }
    this.cache.set(key, { ts: Date.now() });
  }
}

const dedupCache = new LRUCache(
  workerData?.dedupCacheMax || 20000,
  workerData?.dedupTtlMs || 10000
);

/**
 * Normalizes, deduplicates, and enriches a single log item
 */
function processItem(rawItem) {
  const ip = (rawItem.sourceIp || rawItem.ip || "127.0.0.1").trim();
  const category = (rawItem.category || "general").toLowerCase().trim();
  const timestamp = rawItem.timestamp || new Date().toISOString();
  const details = rawItem.details || rawItem.payload?.body || {};
  
  // 1. Fast Deduplication Hash (SHA-256 slice or FNV)
  const dedupKey = `${timestamp}|${category}|${ip}|${JSON.stringify(details)}`;
  const hash = crypto.createHash("sha256").update(dedupKey).digest("hex").slice(0, 24);

  if (dedupCache.has(hash)) {
    return { isDuplicate: true, hash, eventId: rawItem.eventId };
  }
  dedupCache.set(hash);

  // 2. Taxonomy Enrichment
  const meta = CATEGORY_ENRICHMENT[category] || {
    displayName: category.replace(/-/g, " ").replace(/\b\w/g, (c) => c.toUpperCase()),
    severity: "INFO",
    layer: rawItem.layer || "application",
    phase: "app",
    phaseNumber: 1,
  };

  const layer = rawItem.layer || meta.layer;
  const source = rawItem.source || (layer === "network" || layer === "malware-behavioral" || layer === "iot" ? "dataset-replay" : "application-runtime");

  // 3. Normalization into shared MongoDB Schema
  const normalizedDoc = {
    timestamp: new Date(timestamp),
    ip: ip,
    sourceIp: ip,
    endpoint: rawItem.endpoint || "/telemetry",
    method: (rawItem.method || "DATA").toUpperCase(),
    payload: typeof rawItem.payload === "object" && rawItem.payload !== null
      ? rawItem.payload
      : { body: details, query: {}, params: {} },
    category: category,
    layer: layer,
    source: source,
    displayName: meta.displayName,
    severity: meta.severity,
    phase: meta.phase,
    phaseNumber: meta.phaseNumber,
    dataset: rawItem.dataset || meta.dataset || "MERN App",
    details: details,
    campaign_id: rawItem.campaign_id || rawItem.campaignId || undefined,
    eventId: rawItem.eventId || `evt_${Date.now()}_${crypto.randomBytes(4).toString("hex")}`,
    effect: rawItem.effect || null,
    processedAt: new Date().toISOString(),
  };

  return {
    isDuplicate: false,
    document: normalizedDoc,
  };
}

if (parentPort) {
  parentPort.on("message", (msg) => {
    if (!msg || !msg.type) return;

    if (msg.type === "PROCESS_BATCH") {
      const startTime = process.hrtime.bigint();
      const { taskId, items } = msg;
      
      const processedDocs = [];
      let dedupCount = 0;

      for (let i = 0; i < items.length; i++) {
        const res = processItem(items[i]);
        if (res.isDuplicate) {
          dedupCount++;
        } else if (res.document) {
          processedDocs.push(res.document);
        }
      }

      const endTime = process.hrtime.bigint();
      const latencyMs = Number(endTime - startTime) / 1e6;

      parentPort.postMessage({
        type: "BATCH_PROCESSED",
        taskId,
        workerId: workerData?.workerId || 0,
        processedDocs,
        dedupCount,
        inputCount: items.length,
        latencyMs,
      });
    }
  });
}

module.exports = { processItem };
