const os = require("os");
require("dotenv").config();

const config = {
  PORT: parseInt(process.env.PORT || "4000", 10),
  MONGO_URL: process.env.MONGO_URL || "mongodb://127.0.0.1:27017/madps_ingestion_db",
  LOGS_COLLECTION: process.env.LOGS_COLLECTION || "logs",
  FAILED_COLLECTION: process.env.FAILED_COLLECTION || "failed_events",
  SECURITY_COLLECTION: process.env.SECURITY_COLLECTION || "security_events",

  // Security & Authentication Tiers
  INGEST_SERVICE_TOKEN: process.env.INGEST_SERVICE_TOKEN || "madps_sec_svc_tok_9918237b4f2c01_alpha88",
  JWT_SECRET: process.env.JWT_SECRET || "StrongSecretKey_9918237!@#$LabSecure2026",
  WEAK_JWT_SECRET: "secret123",

  // Queue limits & backpressure
  QUEUE_MAX_SIZE: parseInt(process.env.QUEUE_MAX_SIZE || "50000", 10),
  QUEUE_BACKPRESSURE_RATIO: parseFloat(process.env.QUEUE_BACKPRESSURE_RATIO || "0.8"), // 80% capacity -> backpressure
  
  // Rate limiting (per service-token / producer)
  RATE_LIMIT_PER_SOURCE_PER_SEC: parseInt(process.env.RATE_LIMIT_PER_SOURCE_PER_SEC || "5000", 10),
  RATE_LIMIT_PER_SERVICE_TOKEN_PER_SEC: parseInt(process.env.RATE_LIMIT_PER_SERVICE_TOKEN_PER_SEC || "5000", 10),

  // Worker Thread Pool
  INGEST_WORKERS: parseInt(process.env.INGEST_WORKERS || Math.max(2, os.cpus().length).toString(), 10),

  // Micro-batcher thresholds
  BATCH_SIZE: parseInt(process.env.BATCH_SIZE || "500", 10),
  BATCH_FLUSH_INTERVAL_MS: parseInt(process.env.BATCH_FLUSH_INTERVAL_MS || "200", 10),

  // Circuit Breaker settings
  CIRCUIT_BREAKER_FAIL_THRESHOLD: parseInt(process.env.CIRCUIT_BREAKER_FAIL_THRESHOLD || "5", 10),
  CIRCUIT_BREAKER_COOLDOWN_MS: parseInt(process.env.CIRCUIT_BREAKER_COOLDOWN_MS || "10000", 10),

  // Dead-Letter Queue & Retries
  RETRY_INTERVAL_MS: parseInt(process.env.RETRY_INTERVAL_MS || "30000", 10),
  RETRY_BATCH_SIZE: parseInt(process.env.RETRY_BATCH_SIZE || "100", 10),
  MAX_RETRY_ATTEMPTS: parseInt(process.env.MAX_RETRY_ATTEMPTS || "5", 10),

  // LRU Deduplication window
  DEDUP_CACHE_MAX: parseInt(process.env.DEDUP_CACHE_MAX || "20000", 10),
  DEDUP_TTL_MS: parseInt(process.env.DEDUP_TTL_MS || "10000", 10),
};

module.exports = config;
