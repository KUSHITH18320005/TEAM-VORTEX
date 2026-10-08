const { EventEmitter } = require("events");
const config = require("../config");

class MicroBatcher extends EventEmitter {
  constructor(dbClient, circuitBreaker, deadLetterQueue, options = {}) {
    super();
    this.dbClient = dbClient;
    this.circuitBreaker = circuitBreaker;
    this.deadLetterQueue = deadLetterQueue;
    this.collectionName = config.LOGS_COLLECTION;

    this.batchSize = options.batchSize || config.BATCH_SIZE;
    this.flushIntervalMs = options.flushIntervalMs || config.BATCH_FLUSH_INTERVAL_MS;

    this.pendingBuffer = [];
    this.flushTimer = null;
    this.isFlushing = false;

    this.stats = {
      batchesFlushed: 0,
      totalEventsFlushed: 0,
      totalWriteLatencyMs: 0,
      avgWriteLatencyMs: 0,
      avgBatchSize: 0,
      lastFlushTime: null,
    };

    this.startTimer();
  }

  startTimer() {
    if (this.flushTimer) return;
    this.flushTimer = setInterval(() => {
      if (this.pendingBuffer.length > 0 && !this.isFlushing) {
        this.flush().catch((err) => {
          console.error("[BATCH FLUSH ERROR]", err);
        });
      }
    }, this.flushIntervalMs);
  }

  stopTimer() {
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }
  }

  /**
   * Adds a single or array of enriched documents to the buffer.
   * If buffer reaches batchSize, triggers flush immediately.
   */
  addDocuments(docs) {
    if (!docs || docs.length === 0) return;
    if (Array.isArray(docs)) {
      for (let i = 0; i < docs.length; i++) {
        this.pendingBuffer.push(docs[i]);
      }
    } else {
      this.pendingBuffer.push(docs);
    }

    if (this.pendingBuffer.length >= this.batchSize && !this.isFlushing) {
      this.flush().catch((err) => {
        console.error("[BATCH FLUSH ERROR]", err);
      });
    }
  }

  /**
   * Flushes current buffer to MongoDB with Circuit Breaker protection
   */
  async flush() {
    if (this.pendingBuffer.length === 0 || this.isFlushing) return;

    this.isFlushing = true;
    const batch = this.pendingBuffer.slice(0, this.batchSize);
    this.pendingBuffer = this.pendingBuffer.slice(batch.length);

    const startTime = process.hrtime.bigint();

    // 1. Check Circuit Breaker
    if (!this.circuitBreaker.canExecute()) {
      console.warn(`[BATCHER DLQ ROUTE] Circuit breaker is OPEN. Routing batch of ${batch.length} directly to Dead-Letter Queue.`);
      await this.deadLetterQueue.recordFailureBatch(batch, "CIRCUIT_BREAKER_OPEN_DB_UNAVAILABLE");
      this.isFlushing = false;
      return;
    }

    // 2. Format bulkWrite operations (unordered insert)
    const operations = batch.map((doc) => ({
      insertOne: {
        document: {
          timestamp: doc.timestamp instanceof Date ? doc.timestamp : new Date(doc.timestamp),
          ip: doc.ip || "127.0.0.1",
          sourceIp: doc.sourceIp || doc.ip || "127.0.0.1",
          endpoint: doc.endpoint || "/telemetry",
          method: doc.method || "DATA",
          payload: doc.payload || { body: {}, query: {}, params: {} },
          category: doc.category || "general",
          layer: doc.layer || "application",
          source: doc.source || "application-runtime",
          displayName: doc.displayName,
          severity: doc.severity,
          phase: doc.phase,
          phaseNumber: doc.phaseNumber,
          dataset: doc.dataset,
          details: doc.details,
          campaign_id: doc.campaign_id,
          eventId: doc.eventId,
          effect: doc.effect,
          processedAt: doc.processedAt || new Date().toISOString(),
        },
      },
    }));

    try {
      if (!this.dbClient || !this.dbClient.isConnected || !this.dbClient.getDb()) {
        throw new Error("MongoDB client disconnected");
      }

      const col = this.dbClient.getDb().collection(this.collectionName);
      const writeResult = await col.bulkWrite(operations, { ordered: false });

      const endTime = process.hrtime.bigint();
      const latencyMs = Number(endTime - startTime) / 1e6;

      // Update circuit breaker success state
      this.circuitBreaker.recordSuccess();

      // Update batcher metrics
      this.stats.batchesFlushed++;
      this.stats.totalEventsFlushed += batch.length;
      this.stats.totalWriteLatencyMs += latencyMs;
      this.stats.avgWriteLatencyMs = Number((this.stats.totalWriteLatencyMs / this.stats.batchesFlushed).toFixed(2));
      this.stats.avgBatchSize = Number((this.stats.totalEventsFlushed / this.stats.batchesFlushed).toFixed(1));
      this.stats.lastFlushTime = new Date().toISOString();

      // Fan-out to SSE / live feed subscribers
      this.emit("batch_flushed", batch);
    } catch (writeErr) {
      const endTime = process.hrtime.bigint();
      const latencyMs = Number(endTime - startTime) / 1e6;

      // Update circuit breaker failure state
      this.circuitBreaker.recordFailure(writeErr);

      // Route failed batch documents to Dead-Letter Queue
      await this.deadLetterQueue.recordFailureBatch(batch, `BULK_WRITE_FAILED: ${writeErr.message}`);
    } finally {
      this.isFlushing = false;
      // If remaining buffer is still above threshold, flush again immediately
      if (this.pendingBuffer.length >= this.batchSize) {
        setImmediate(() => {
          this.flush().catch(() => {});
        });
      }
    }
  }

  getStats() {
    return {
      pendingBufferSize: this.pendingBuffer.length,
      batchSize: this.batchSize,
      flushIntervalMs: this.flushIntervalMs,
      batchesFlushed: this.stats.batchesFlushed,
      totalEventsFlushed: this.stats.totalEventsFlushed,
      avgBatchSize: this.stats.avgBatchSize,
      avgWriteLatencyMs: this.stats.avgWriteLatencyMs,
      lastFlushTime: this.stats.lastFlushTime,
    };
  }
}

module.exports = { MicroBatcher };
