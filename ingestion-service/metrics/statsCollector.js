class StatsCollector {
  constructor() {
    this.acceptedCount = 0;
    this.rejectedValidationCount = 0;
    this.rejectedRateLimitCount = 0;
    this.rejectedBackpressureCount = 0;
    this.rejectedAuthCount = 0;
    this.totalIngressRequests = 0;

    // Rolling windows: 1-second buckets for 60 seconds
    this.buckets = new Array(60).fill(0);
    this.bucketTimestamps = new Array(60).fill(0);
    this.currentBucketIndex = 0;

    this.startTime = Date.now();

    // Tick every second to advance rolling window
    this.ticker = setInterval(() => {
      this.advanceBucket();
    }, 1000);
  }

  advanceBucket() {
    const nowSec = Math.floor(Date.now() / 1000);
    this.currentBucketIndex = (this.currentBucketIndex + 1) % 60;
    this.buckets[this.currentBucketIndex] = 0;
    this.bucketTimestamps[this.currentBucketIndex] = nowSec;
  }

  recordAccepted(count = 1) {
    this.acceptedCount += count;
    this.totalIngressRequests += count;
    const idx = this.currentBucketIndex;
    this.buckets[idx] = (this.buckets[idx] || 0) + count;
  }

  recordRejectedValidation(count = 1) {
    this.rejectedValidationCount += count;
    this.totalIngressRequests += count;
  }

  recordRejectedRateLimit(count = 1) {
    this.rejectedRateLimitCount += count;
    this.totalIngressRequests += count;
  }

  recordRejectedBackpressure(count = 1) {
    this.rejectedBackpressureCount += count;
    this.totalIngressRequests += count;
  }

  recordRejectedAuth(count = 1) {
    this.rejectedAuthCount += count;
    this.totalIngressRequests += count;
  }

  /**
   * Calculates rolling events/sec over recent N seconds
   */
  getRollingRate(seconds = 10) {
    const nowSec = Math.floor(Date.now() / 1000);
    let totalEvents = 0;
    let validSeconds = 0;

    for (let i = 0; i < 60; i++) {
      const ts = this.bucketTimestamps[i];
      if (ts && nowSec - ts <= seconds && nowSec - ts >= 0) {
        totalEvents += this.buckets[i];
        validSeconds++;
      }
    }

    const divisor = Math.max(1, Math.min(seconds, Math.floor((Date.now() - this.startTime) / 1000) || 1));
    return Number((totalEvents / divisor).toFixed(2));
  }

  getSnapshot(queue, workerPool, batcher, circuitBreaker, dlq) {
    const rate10s = this.getRollingRate(10);
    const rate60s = this.getRollingRate(60);

    const queueStats = queue ? queue.getStats() : {};
    const workerStats = workerPool ? workerPool.getStats() : {};
    const batcherStats = batcher ? batcher.getStats() : {};
    const cbStats = circuitBreaker ? circuitBreaker.getStats() : {};

    return {
      timestamp: new Date().toISOString(),
      uptimeSeconds: Math.floor((Date.now() - this.startTime) / 1000),
      throughput: {
        eventsPerSecond10s: rate10s,
        eventsPerSecond60s: rate60s,
        totalAccepted: this.acceptedCount,
        totalRejectedValidation: this.rejectedValidationCount,
        totalRejectedRateLimit: this.rejectedRateLimitCount,
        totalRejectedBackpressure: this.rejectedBackpressureCount,
        totalRejectedAuth: this.rejectedAuthCount,
        totalAuthRejections: this.rejectedAuthCount,
        totalIngress: this.totalIngressRequests,
      },
      queue: queueStats,
      workers: workerStats,
      batchWriter: batcherStats,
      circuitBreaker: cbStats,
      dedup: {
        totalDedupHits: workerStats.totalDedup || 0,
      },
      deadLetterQueue: dlq ? dlq.stats : {},
    };
  }

  stop() {
    if (this.ticker) {
      clearInterval(this.ticker);
      this.ticker = null;
    }
  }
}

module.exports = { StatsCollector };
