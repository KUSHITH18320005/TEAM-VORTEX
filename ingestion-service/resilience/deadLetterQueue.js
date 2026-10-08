const { EventEmitter } = require("events");
const config = require("../config");

class DeadLetterQueue extends EventEmitter {
  constructor(dbClient, options = {}) {
    super();
    this.dbClient = dbClient;
    this.collectionName = config.FAILED_COLLECTION;
    this.retryIntervalMs = options.retryIntervalMs || config.RETRY_INTERVAL_MS;
    this.maxRetryAttempts = options.maxRetryAttempts || config.MAX_RETRY_ATTEMPTS;
    this.retryBatchSize = options.retryBatchSize || config.RETRY_BATCH_SIZE;

    // In-memory fallback DLQ buffer for resilience during complete database disconnects
    this.memoryDlq = [];
    this.memoryDlqHead = 0;

    this.stats = {
      totalFailedEvents: 0,
      inMemoryCount: 0,
      retriesAttempted: 0,
      retrySuccesses: 0,
      retryFailures: 0,
      permanentlyFailed: 0,
      lastRetryRun: null,
    };

    this.reprocessCallback = null;
    this.retryTimer = null;
  }

  setReprocessHandler(callback) {
    this.reprocessCallback = callback;
  }

  startRetryScheduler() {
    if (this.retryTimer) return;
    this.retryTimer = setInterval(() => {
      this.runRetryCycle().catch((err) => {
        console.error("[DLQ RETRY ERROR]", err);
      });
    }, this.retryIntervalMs);
    console.log(`[DLQ] Background retry scheduler initialized (Interval: ${this.retryIntervalMs / 1000}s, Batch: ${this.retryBatchSize}).`);
  }

  stopRetryScheduler() {
    if (this.retryTimer) {
      clearInterval(this.retryTimer);
      this.retryTimer = null;
    }
  }

  /**
   * Records a failed event to MongoDB failed_events collection (or in-memory DLQ buffer)
   */
  async recordFailure(originalPayload, failureReason, retryCount = 0) {
    this.stats.totalFailedEvents++;

    const failedDoc = {
      originalPayload,
      failureReason: typeof failureReason === "string" ? failureReason : JSON.stringify(failureReason),
      timestamp: new Date(),
      retryCount: retryCount,
      status: retryCount >= this.maxRetryAttempts ? "permanently_failed" : "pending_retry",
      lastAttemptAt: new Date(),
    };

    if (failedDoc.status === "permanently_failed") {
      this.stats.permanentlyFailed++;
    }

    try {
      if (this.dbClient && this.dbClient.isConnected && this.dbClient.getDb()) {
        const col = this.dbClient.getDb().collection(this.collectionName);
        await col.insertOne(failedDoc);
        return { persisted: "mongodb", id: failedDoc._id };
      }
    } catch (e) {
      // MongoDB write failed, fallback to in-memory DLQ
    }

    // Buffer in memory
    this.memoryDlq.push(failedDoc);
    this.stats.inMemoryCount = this.memoryDlq.length - this.memoryDlqHead;
    return { persisted: "memory", doc: failedDoc };
  }

  /**
   * Records a batch of failed events (e.g. from an open circuit breaker batch)
   */
  async recordFailureBatch(payloadArray, failureReason) {
    if (!payloadArray || payloadArray.length === 0) return;
    const now = new Date();

    const docs = payloadArray.map((p) => ({
      originalPayload: p,
      failureReason: typeof failureReason === "string" ? failureReason : JSON.stringify(failureReason),
      timestamp: now,
      retryCount: 0,
      status: "pending_retry",
      lastAttemptAt: now,
    }));

    this.stats.totalFailedEvents += docs.length;

    try {
      if (this.dbClient && this.dbClient.isConnected && this.dbClient.getDb()) {
        const col = this.dbClient.getDb().collection(this.collectionName);
        await col.insertMany(docs, { ordered: false });
        return { count: docs.length, persisted: "mongodb" };
      }
    } catch (e) {
      // Fallback
    }

    for (const d of docs) {
      this.memoryDlq.push(d);
    }
    this.stats.inMemoryCount = this.memoryDlq.length - this.memoryDlqHead;
    return { count: docs.length, persisted: "memory" };
  }

  /**
   * Re-processes failed events with exponential backoff
   */
  async runRetryCycle() {
    this.stats.lastRetryRun = new Date().toISOString();
    if (!this.reprocessCallback) return;

    let itemsToRetry = [];

    // 1. Check in-memory DLQ buffer first
    if (this.memoryDlq.length - this.memoryDlqHead > 0) {
      const count = Math.min(this.memoryDlq.length - this.memoryDlqHead, this.retryBatchSize);
      itemsToRetry = this.memoryDlq.slice(this.memoryDlqHead, this.memoryDlqHead + count);
      this.memoryDlqHead += count;
      if (this.memoryDlqHead >= this.memoryDlq.length) {
        this.memoryDlq = [];
        this.memoryDlqHead = 0;
      }
      this.stats.inMemoryCount = this.memoryDlq.length - this.memoryDlqHead;
    }

    // 2. Fetch pending retries from MongoDB failed_events if available
    if (itemsToRetry.length < this.retryBatchSize && this.dbClient && this.dbClient.isConnected && this.dbClient.getDb()) {
      try {
        const col = this.dbClient.getDb().collection(this.collectionName);
        const dbDocs = await col
          .find({ status: "pending_retry", retryCount: { $lt: this.maxRetryAttempts } })
          .limit(this.retryBatchSize - itemsToRetry.length)
          .toArray();

        if (dbDocs && dbDocs.length > 0) {
          itemsToRetry.push(...dbDocs);
        }
      } catch (e) {}
    }

    if (itemsToRetry.length === 0) return;

    console.log(`[DLQ RETRY] Attempting re-processing of ${itemsToRetry.length} failed events...`);
    this.stats.retriesAttempted += itemsToRetry.length;

    for (const item of itemsToRetry) {
      try {
        const success = await this.reprocessCallback(item.originalPayload);
        if (success) {
          this.stats.retrySuccesses++;
          if (item._id && this.dbClient && this.dbClient.isConnected && this.dbClient.getDb()) {
            await this.dbClient.getDb().collection(this.collectionName).updateOne(
              { _id: item._id },
              { $set: { status: "resolved", resolvedAt: new Date() } }
            ).catch(() => {});
          }
        } else {
          throw new Error("Reprocess returned false");
        }
      } catch (err) {
        this.stats.retryFailures++;
        const newRetryCount = (item.retryCount || 0) + 1;
        const newStatus = newRetryCount >= this.maxRetryAttempts ? "permanently_failed" : "pending_retry";
        if (newStatus === "permanently_failed") {
          this.stats.permanentlyFailed++;
          console.warn(`[DLQ] Event exceeded max retry attempts (${this.maxRetryAttempts}). Marked permanently_failed.`);
        }

        if (item._id && this.dbClient && this.dbClient.isConnected && this.dbClient.getDb()) {
          await this.dbClient.getDb().collection(this.collectionName).updateOne(
            { _id: item._id },
            {
              $set: {
                retryCount: newRetryCount,
                status: newStatus,
                lastAttemptAt: new Date(),
                lastError: err.message,
              },
            }
          ).catch(() => {});
        } else if (newStatus === "pending_retry") {
          // Re-insert into memory queue
          item.retryCount = newRetryCount;
          item.lastAttemptAt = new Date();
          this.memoryDlq.push(item);
          this.stats.inMemoryCount = this.memoryDlq.length - this.memoryDlqHead;
        }
      }
    }
  }

  async getStats() {
    let dbPending = 0;
    let dbResolved = 0;
    let dbPermanentlyFailed = 0;

    if (this.dbClient && this.dbClient.isConnected && this.dbClient.getDb()) {
      try {
        const col = this.dbClient.getDb().collection(this.collectionName);
        dbPending = await col.countDocuments({ status: "pending_retry" });
        dbResolved = await col.countDocuments({ status: "resolved" });
        dbPermanentlyFailed = await col.countDocuments({ status: "permanently_failed" });
      } catch (e) {}
    }

    return {
      totalFailedEvents: this.stats.totalFailedEvents,
      inMemoryPending: this.stats.inMemoryCount,
      dbPending,
      dbResolved,
      permanentlyFailed: Math.max(this.stats.permanentlyFailed, dbPermanentlyFailed),
      retriesAttempted: this.stats.retriesAttempted,
      retrySuccesses: this.stats.retrySuccesses,
      retryFailures: this.stats.retryFailures,
      lastRetryRun: this.stats.lastRetryRun,
    };
  }
}

module.exports = { DeadLetterQueue };
