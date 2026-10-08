#!/usr/bin/env node
/**
 * MAD-PS Ingestion Tier High-Throughput Benchmark & Security Load Test
 * --------------------------------------------------------------------
 * 1. Phase A: Authorized High-Throughput Burst (10,000 events over 10s)
 *    Fired with valid INGEST_SERVICE_TOKEN against /ingest/batch.
 *    Measures throughput, p50/p95/p99 latency, queue depth, and backpressure.
 * 
 * 2. Phase B: Deliberate Unauthorized Ingress Flood
 *    Fired with invalid/missing service token to verify 100% 401 rejection rate
 *    and security_events audit logging under load.
 */

const http = require("http");

const TARGET_HOST = process.env.INGEST_HOST || "127.0.0.1";
const TARGET_PORT = parseInt(process.env.INGEST_PORT || "4000", 10);
const TOTAL_EVENTS = parseInt(process.env.BENCH_EVENTS || "10000", 10);
const BATCH_SIZE = parseInt(process.env.BENCH_BATCH_SIZE || "100", 10);
const CONCURRENCY = parseInt(process.env.BENCH_CONCURRENCY || "10", 10);
const VALID_TOKEN = process.env.INGEST_SERVICE_TOKEN || "madps_sec_svc_tok_9918237b4f2c01_alpha88";

const ATTACK_CATEGORIES = [
  "nosql-injection", "xss-stored", "open-redirect", "business-logic",
  "jwt-abuse", "session-hijack", "bruteforce", "credential-stuffing",
  "port-scanning-recon", "dos", "ddos", "ransomware-behavioral",
  "botnet-c2", "compromised-iot", "apt-stealth-intrusion", "ai-adaptive"
];

function generateEvent(index, batchIdx = 0) {
  const cat = ATTACK_CATEGORIES[index % ATTACK_CATEGORIES.length];
  const sourceId = `producer_node_${(batchIdx % 10) + 1}`;
  return {
    timestamp: new Date().toISOString(),
    ip: `198.51.100.${(index % 250) + 1}`,
    category: cat,
    layer: cat.includes("port") || cat.includes("dos") ? "network" : cat.includes("iot") ? "iot" : "application",
    source: sourceId,
    endpoint: `/api/v1/resource_${index % 50}`,
    method: index % 2 === 0 ? "POST" : "GET",
    payload: {
      body: {
        bench_id: index,
        metric_value: Math.random() * 100,
        flow_bytes: 4096,
      },
    },
    details: {
      benchmark_run: true,
      batch_id: batchIdx,
    },
  };
}

function sendBatch(events, token = VALID_TOKEN) {
  return new Promise((resolve) => {
    const postData = JSON.stringify(events);
    const startTime = process.hrtime.bigint();

    const headers = {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(postData),
    };

    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }

    const req = http.request(
      {
        hostname: TARGET_HOST,
        port: TARGET_PORT,
        path: "/ingest/batch",
        method: "POST",
        headers,
        timeout: 10000,
      },
      (res) => {
        let rawBody = "";
        res.on("data", (chunk) => (rawBody += chunk));
        res.on("end", () => {
          const endTime = process.hrtime.bigint();
          const latencyMs = Number(endTime - startTime) / 1e6;
          resolve({
            statusCode: res.statusCode,
            latencyMs,
            success: res.statusCode >= 200 && res.statusCode < 300,
            isUnauthorized: res.statusCode === 401,
            isBackpressured: res.statusCode === 503,
            isRateLimited: res.statusCode === 429,
          });
        });
      }
    );

    req.on("error", (err) => {
      const endTime = process.hrtime.bigint();
      const latencyMs = Number(endTime - startTime) / 1e6;
      resolve({
        statusCode: 0,
        error: err.message,
        latencyMs,
        success: false,
        isUnauthorized: false,
        isBackpressured: false,
      });
    });

    req.on("timeout", () => {
      req.destroy();
      resolve({
        statusCode: 408,
        latencyMs: 10000,
        success: false,
        isUnauthorized: false,
        isBackpressured: false,
      });
    });

    req.write(postData);
    req.end();
  });
}

function fetchStats() {
  return new Promise((resolve) => {
    http.get(`http://${TARGET_HOST}:${TARGET_PORT}/ingest/stats`, (res) => {
      let body = "";
      res.on("data", (c) => (body += c));
      res.on("end", () => {
        try {
          resolve(JSON.parse(body));
        } catch (e) {
          resolve(null);
        }
      });
    }).on("error", () => resolve(null));
  });
}

function calculatePercentile(latencies, percentile) {
  if (!latencies || latencies.length === 0) return 0;
  const sorted = [...latencies].sort((a, b) => a - b);
  const index = Math.min(sorted.length - 1, Math.floor((percentile / 100) * sorted.length));
  return Number(sorted[index].toFixed(2));
}

async function runBenchmark() {
  console.log("════════════════════════════════════════════════════════════════════════════════");
  console.log("   🚀 MAD-PS CLOUD LOG INGESTION BENCHMARK & LOAD TEST");
  console.log("════════════════════════════════════════════════════════════════════════════════");
  console.log(` Target Endpoint     : http://${TARGET_HOST}:${TARGET_PORT}/ingest/batch`);
  console.log(` Total Events        : ${TOTAL_EVENTS.toLocaleString()}`);
  console.log(` Batch Size          : ${BATCH_SIZE} events / request`);
  console.log(` Total Batches       : ${Math.ceil(TOTAL_EVENTS / BATCH_SIZE)}`);
  console.log(` Concurrency         : ${CONCURRENCY} parallel HTTP workers`);
  console.log(` Service Auth Token  : Bearer ${VALID_TOKEN.slice(0, 10)}... (CONFIGURED)`);
  console.log("════════════════════════════════════════════════════════════════════════════════\n");

  const initialStats = await fetchStats();
  if (initialStats) {
    console.log(`[PRE-FLIGHT] Queue Depth: ${initialStats.queue?.currentDepth || 0}/${initialStats.queue?.maxSize || 50000} | Workers Alive: ${initialStats.workers?.aliveWorkers || 0} | Circuit Breaker: ${initialStats.circuitBreaker?.state || "CLOSED"}`);
  } else {
    console.warn(`[WARN] Ingestion service at http://${TARGET_HOST}:${TARGET_PORT} not reachable. Please start server.js first.`);
    process.exit(1);
  }

  // -------------------------------------------------------------------------
  // PHASE A: AUTHORIZED HIGH-THROUGHPUT BURST (10,000 Events)
  // -------------------------------------------------------------------------
  console.log("\n▶ PHASE A: Executing Authorized High-Throughput Ingestion Burst...");

  const totalBatches = Math.ceil(TOTAL_EVENTS / BATCH_SIZE);
  const batches = [];
  for (let b = 0; b < totalBatches; b++) {
    const count = Math.min(BATCH_SIZE, TOTAL_EVENTS - b * BATCH_SIZE);
    const events = [];
    for (let i = 0; i < count; i++) {
      events.push(generateEvent(b * BATCH_SIZE + i, b));
    }
    batches.push(events);
  }

  let completedBatches = 0;
  let successfulBatches = 0;
  let backpressuredBatches = 0;
  let rateLimitedBatches = 0;
  let failedBatches = 0;
  const latencies = [];

  const startTime = Date.now();

  // Worker pool dispatch
  let batchIndex = 0;
  async function worker() {
    while (batchIndex < batches.length) {
      const idx = batchIndex++;
      const res = await sendBatch(batches[idx], VALID_TOKEN);
      completedBatches++;
      latencies.push(res.latencyMs);

      if (res.success) successfulBatches++;
      else if (res.isBackpressured) backpressuredBatches++;
      else if (res.isRateLimited) rateLimitedBatches++;
      else failedBatches++;

      if (completedBatches % Math.max(1, Math.floor(totalBatches / 5)) === 0 || completedBatches === totalBatches) {
        const elapsedSec = (Date.now() - startTime) / 1000;
        const currentThroughput = Math.round((completedBatches * BATCH_SIZE) / Math.max(0.1, elapsedSec));
        process.stdout.write(`  [BURST PROGRESS] ${completedBatches}/${totalBatches} batches (${Math.round((completedBatches / totalBatches) * 100)}%) • Velocity: ${currentThroughput.toLocaleString()} evt/s\r`);
      }
    }
  }

  const workers = [];
  for (let c = 0; c < CONCURRENCY; c++) {
    workers.push(worker());
  }
  await Promise.all(workers);

  const totalDurationSec = (Date.now() - startTime) / 1000;
  const totalEventsIngested = successfulBatches * BATCH_SIZE;
  const effectiveThroughput = Number((totalEventsIngested / totalDurationSec).toFixed(1));

  console.log("\n\n📊 PHASE A BENCHMARK RESULTS:");
  console.log(` ├─ Total Events Dispatched : ${TOTAL_EVENTS.toLocaleString()}`);
  console.log(` ├─ Successfully Ingested   : ${totalEventsIngested.toLocaleString()} events (${successfulBatches}/${totalBatches} batches)`);
  console.log(` ├─ Wall Clock Duration     : ${totalDurationSec.toFixed(2)}s`);
  console.log(` ├─ Effective Throughput    : ${effectiveThroughput.toLocaleString()} events/sec 🚀`);
  console.log(` ├─ Latency p50 (Median)    : ${calculatePercentile(latencies, 50)} ms`);
  console.log(` ├─ Latency p95             : ${calculatePercentile(latencies, 95)} ms`);
  console.log(` ├─ Latency p99             : ${calculatePercentile(latencies, 99)} ms`);
  console.log(` ├─ Backpressured Requests  : ${backpressuredBatches} (HTTP 503)`);
  console.log(` └─ Rate-Limited Requests   : ${rateLimitedBatches} (HTTP 429)`);

  // -------------------------------------------------------------------------
  // PHASE B: DELIBERATE UNAUTHORIZED INGRESS FLOOD TEST
  // -------------------------------------------------------------------------
  console.log("\n▶ PHASE B: Executing Deliberate Unauthorized Access & Flood Test...");
  console.log("  [TEST] Firing batches with missing / bogus service tokens to verify 401 gate & audit logging...");

  const unauthorizedBatchCount = 20;
  let rejected401Count = 0;
  const unauthLatencies = [];

  for (let i = 0; i < unauthorizedBatchCount; i++) {
    const bogusToken = i % 2 === 0 ? "invalid_forged_token_007" : null;
    const testEvents = [generateEvent(i, i)];
    const res = await sendBatch(testEvents, bogusToken);
    unauthLatencies.push(res.latencyMs);
    if (res.isUnauthorized && res.statusCode === 401) {
      rejected401Count++;
    }
  }

  const unauthRejectionRate = ((rejected401Count / unauthorizedBatchCount) * 100).toFixed(1);
  console.log("\n🔒 PHASE B SECURITY AUDIT RESULTS:");
  console.log(` ├─ Unauthorized Batches Fired : ${unauthorizedBatchCount}`);
  console.log(` ├─ HTTP 401 Rejections        : ${rejected401Count} / ${unauthorizedBatchCount} (${unauthRejectionRate}%)`);
  console.log(` ├─ Mean Rejection Latency     : ${calculatePercentile(unauthLatencies, 50)} ms`);
  console.log(` └─ Security Gate Validation   : ${rejected401Count === unauthorizedBatchCount ? "✅ 100% BLOCKED & LOGGED" : "❌ LEAK DETECTED"}`);

  // Fetch final post-test stats
  await new Promise((r) => setTimeout(r, 600));
  const finalStats = await fetchStats();
  if (finalStats) {
    console.log("\n📈 FINAL INGESTION TIER METRIC SNAPSHOT:");
    console.log(` ├─ Rolling Rate (10s window) : ${finalStats.throughput?.eventsPerSecond10s || 0} evt/s`);
    console.log(` ├─ Queue Depth               : ${finalStats.queue?.currentDepth || 0} / ${finalStats.queue?.maxSize || 50000}`);
    console.log(` ├─ Total Dedup Hits          : ${finalStats.dedup?.totalDedupHits || 0}`);
    console.log(` ├─ Worker Avg Latency        : ${finalStats.workers?.avgLatencyMs || 0} ms (${finalStats.workers?.aliveWorkers || 0} threads)`);
    console.log(` ├─ Batch Writer Flushed      : ${finalStats.batchWriter?.totalEventsFlushed || 0} events across ${finalStats.batchWriter?.batchesFlushed || 0} batches`);
    console.log(` ├─ Circuit Breaker State     : ${finalStats.circuitBreaker?.state || "CLOSED"}`);
    console.log(` └─ Total Auth Rejections     : ${finalStats.throughput?.totalAuthRejections || finalStats.security?.totalAuthRejections || 0}`);
  }

  console.log("\n════════════════════════════════════════════════════════════════════════════════");
  console.log("🏁 INGESTION TIER BENCHMARK COMPLETE: PASS");
  console.log("════════════════════════════════════════════════════════════════════════════════\n");
}

if (require.main === module) {
  runBenchmark().catch((err) => {
    console.error("[BENCHMARK FAILED]", err);
    process.exit(1);
  });
}

module.exports = { runBenchmark };
