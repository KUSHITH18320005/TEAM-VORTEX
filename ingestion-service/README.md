# MAD-PS Cloud Log Ingestion & Parallel Processing Tier

The **MAD-PS Ingestion Service** (`Z/ingestion-service/`) is the dedicated, high-throughput gateway sitting between telemetry producers (MERN application runtime, dataset-replay module, Attack Console simulation triggers) and the persistent MongoDB `logs` collection (consumed downstream by the Phase 4 ML detection engine).

---

## 1. System Architecture

```
                                  PRODUCER TIER
   [ MERN Application ]    [ Dataset Replay (Python) ]    [ Attack Console / Simulator ]
            │                           │                              │
            └─────────── Authorization: Bearer <INGEST_SERVICE_TOKEN> ─┘
                                        │
                                        ▼
══════════════════════════════════════════════════════════════════════════════════════════
                            MAD-PS INGESTION SERVICE (:4000)
══════════════════════════════════════════════════════════════════════════════════════════
 1. Ingress & Security Gate:
    ├─ Service-to-Service Auth: Bearer Token Validation (401 on missing/invalid)
    ├─ Security Audit: Logs unauthorized attempts to `security_events` collection
    ├─ Token Rate Limiter: 5,000 req/sec per token bucket (429 + Retry-After)
    └─ Schema Validation: Strict Zod parsing on `/ingest/log` and `/ingest/batch` (400)
                                        │
 2. Backpressure-Aware Queue:
    └─ In-Memory Bounded Ring Buffer (Max Depth: 50,000 events)
       └─ Backpressure Engaged at 80% (40,000 events) ➔ HTTP 503 + Retry-After
                                        │
 3. Multi-Threaded Parallel Processing:
    └─ Node.js `worker_threads` Pool (Default: 4 CPU threads)
       ├─ Sub-millisecond LRU Cache Deduplication (SHA-256 event fingerprint)
       ├─ MITRE ATT&CK / Taxonomy Metadata Enrichment
       └─ Severity & Layer Normalization
                                        │
 4. Resilience & Micro-Batching:
    ├─ MicroBatcher: Unordered `bulkWrite` every 200ms OR 500 events
    ├─ Circuit Breaker: Tripped to OPEN on 5 consecutive MongoDB write failures
    ├─ Live Fan-Out: Broadcasts batched events to Server-Sent Events (`/ingest/events`)
    └─ Dead-Letter Queue:
       ├─ Unwritable / Circuit-Open events ➔ `failed_events` collection
       ├─ Background Retry Engine (every 30s, max 5 attempts)
       └─ Admin-Only Manual Replay Trigger (`POST /ingest/admin/retry-failed`)
══════════════════════════════════════════════════════════════════════════════════════════
                                        │
                                        ▼
                              STORAGE & CONSUMERS
               ┌────────────────────────┴────────────────────────┐
               ▼                                                 ▼
     MongoDB `logs` Collection                       Live Attack Console
    (Target for Phase 4 ML)                     (Real-Time Ingestion Stats Strip)
```

---

## 2. Authentication & Permission Tiers

| Endpoint | Method | Auth Tier | Credential Required | Behavior on Failure |
| :--- | :---: | :---: | :--- | :--- |
| `/ingest/log` | `POST` | **Service-to-Service** | `Authorization: Bearer <INGEST_SERVICE_TOKEN>` | **401 Unauthorized** + logged to `security_events` |
| `/ingest/batch` | `POST` | **Service-to-Service** | `Authorization: Bearer <INGEST_SERVICE_TOKEN>` | **401 Unauthorized** + logged to `security_events` |
| `/ingest/admin/retry-failed`| `POST` | **Admin JWT** | `Authorization: Bearer <ADMIN_JWT>` | **401/403 Forbidden** (requires `role: "admin"`) |
| `/ingest/stats` | `GET` | **Open / Read-Only** | None (Public monitoring) | 200 JSON snapshot |
| `/ingest/events` | `GET` | **Open / Stream** | None (Server-Sent Events) | 200 Event Stream |
| `/health` | `GET` | **Open / Liveness** | None | 200 OK |
| `/ready` | `GET` | **Open / Readiness** | None | 200 (Ready) / 503 (Overloaded or CB Open) |

---

## 3. Configuration & Environment Variables

Create `.env` in `ingestion-service/` or provide environment variables:

```ini
# Server Port & Storage
PORT=4000
MONGO_URL=mongodb://127.0.0.1:27017/zerodha_lab
LOGS_COLLECTION=logs
FAILED_COLLECTION=failed_events
SECURITY_COLLECTION=security_events

# Service Authentication Secret
INGEST_SERVICE_TOKEN=madps_sec_svc_tok_9918237b4f2c01_alpha88
JWT_SECRET=StrongSecretKey_9918237!@#$LabSecure2026

# Concurrency & Ingress Queue
INGEST_WORKERS=4
QUEUE_MAX_SIZE=50000
QUEUE_BACKPRESSURE_RATIO=0.8
RATE_LIMIT_PER_SERVICE_TOKEN_PER_SEC=5000

# Micro-Batcher & Circuit Breaker
BATCH_SIZE=500
BATCH_FLUSH_INTERVAL_MS=200
CIRCUIT_BREAKER_FAIL_THRESHOLD=5
CIRCUIT_BREAKER_COOLDOWN_MS=10000

# Dead-Letter Queue & Retries
RETRY_INTERVAL_MS=30000
RETRY_BATCH_SIZE=100
MAX_RETRY_ATTEMPTS=5
```

### Generating a New Service Token
To generate a cryptographically strong random token:
```bash
node -e "console.log('madps_svc_' + require('crypto').randomBytes(24).toString('hex'))"
```

---

## 4. How to Run

### Standalone Execution
```bash
cd ingestion-service
npm install
node server.js
```

### Starting as Daemon
```bash
node server.js
# Output:
# 🚀 MAD-PS Ingestion Service running on http://127.0.0.1:4000
#    - Auth: Service Token Authentication Required
#    - Workers: 4 worker threads
#    - Queue Max Depth: 50000 (Backpressure at 40000)
#    - Batch Flush: 500 events or 200ms
```

---

## 5. High-Throughput Benchmark & Security Load Testing

The service includes a built-in benchmark script (`loadtest.js`) verifying throughput, latency percentiles, queue dynamics, and security rejection behavior under heavy burst traffic:

```bash
cd ingestion-service
node loadtest.js
```

### Benchmark Capabilities:
1. **Phase A (Authorized Ingestion Burst)**:
   - Dispatches **10,000 events** in batches of 100 with 10 concurrent HTTP workers using valid `Authorization: Bearer <INGEST_SERVICE_TOKEN>`.
   - Measures effective throughput (`events/sec`), median latency (`p50`), tail latency (`p95`, `p99`), and backpressure counts.
2. **Phase B (Unauthorized Ingress Flood)**:
   - Floods the gateway with invalid and missing token payloads.
   - Verifies **100% HTTP 401 rejections** and confirms audit entries recorded in `security_events`.

---

## 6. Production Scaling Roadmap (Future Scope)

For enterprise-scale, distributed production deployments beyond the single-machine academic testbed:

1. **Distributed Queue Buffer (Kafka / Apache Pulsar / Redis Streams)**:
   - *Current Design*: High-performance in-process ring buffer (`BoundedQueue`) optimized for zero-dependency local execution.
   - *Production Path*: Replace the in-process queue with Apache Kafka or Redis Streams with BullMQ to enable distributed horizontal scaling across multi-node ingestion clusters with persistent partition offsets.
2. **Horizontal Containerized Worker Fleets**:
   - *Current Design*: CPU-bound parallelism via Node.js `worker_threads`.
   - *Production Path*: Decouple workers into autoscaling Kubernetes Pods (KEDA) scaling dynamically based on Kafka consumer group lag.
3. **Hardware Secrets Management (HashiCorp Vault / AWS Secrets Manager)**:
   - *Current Design*: Environment variable injection (`.env`).
   - *Production Path*: Dynamic secret rotation with short-lived mTLS client certificates and Vault-issued OAuth2/OIDC service tokens.
4. **Time-Series / Columnar Storage Tier (ClickHouse / TimescaleDB)**:
   - *Current Design*: Bulk writes to MongoDB `logs` collection.
   - *Production Path*: Stream raw telemetry directly into ClickHouse for ultra-fast vector aggregation and OLAP queries during Phase 4 ML training.
