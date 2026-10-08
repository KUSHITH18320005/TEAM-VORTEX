const { Worker } = require("worker_threads");
const path = require("path");
const config = require("../config");

class WorkerPool {
  constructor(poolSize = config.INGEST_WORKERS) {
    this.poolSize = poolSize;
    this.workers = [];
    this.nextWorkerIndex = 0;
    this.taskIdCounter = 0;
    this.pendingTasks = new Map();
    this.stats = [];
    this.initPool();
  }

  initPool() {
    const workerScript = path.join(__dirname, "ingestWorker.js");

    for (let i = 0; i < this.poolSize; i++) {
      this.spawnWorker(i, workerScript);
    }
  }

  spawnWorker(workerId, workerScript) {
    const worker = new Worker(workerScript, {
      workerData: {
        workerId,
        dedupCacheMax: config.DEDUP_CACHE_MAX,
        dedupTtlMs: config.DEDUP_TTL_MS,
      },
    });

    const statRecord = {
      workerId,
      processedCount: 0,
      activeTasks: 0,
      totalLatencyMs: 0,
      avgLatencyMs: 0,
      dedupHits: 0,
      isAlive: true,
      lastActive: Date.now(),
    };
    this.stats[workerId] = statRecord;

    worker.on("message", (msg) => {
      if (!msg || !msg.taskId) return;
      const deferred = this.pendingTasks.get(msg.taskId);
      if (deferred) {
        this.pendingTasks.delete(msg.taskId);
        statRecord.activeTasks = Math.max(0, statRecord.activeTasks - 1);
        statRecord.processedCount += msg.inputCount || 0;
        statRecord.dedupHits += msg.dedupCount || 0;
        statRecord.totalLatencyMs += msg.latencyMs || 0;
        const tasksCompleted = statRecord.processedCount;
        statRecord.avgLatencyMs = tasksCompleted > 0
          ? Number((statRecord.totalLatencyMs / (tasksCompleted / (msg.inputCount || 1))).toFixed(3))
          : 0;
        statRecord.lastActive = Date.now();

        deferred.resolve(msg);
      }
    });

    worker.on("error", (err) => {
      console.error(`[WORKER ERROR] Worker ${workerId} encountered error:`, err);
      statRecord.isAlive = false;
    });

    worker.on("exit", (code) => {
      if (code !== 0) {
        console.warn(`[WORKER RESTART] Worker ${workerId} exited with code ${code}. Respawning...`);
      }
      statRecord.isAlive = false;
      // Respawn worker
      setTimeout(() => {
        this.spawnWorker(workerId, workerScript);
      }, 500);
    });

    this.workers[workerId] = worker;
  }

  /**
   * Distribute batch to least-loaded worker (or round-robin)
   */
  processBatch(items) {
    if (!items || items.length === 0) {
      return Promise.resolve({ processedDocs: [], dedupCount: 0, latencyMs: 0 });
    }

    return new Promise((resolve, reject) => {
      // Find worker with lowest active tasks among alive workers
      let chosenWorkerId = -1;
      let minTasks = Infinity;

      for (let i = 0; i < this.poolSize; i++) {
        const stat = this.stats[i];
        if (stat && stat.isAlive && stat.activeTasks < minTasks) {
          minTasks = stat.activeTasks;
          chosenWorkerId = i;
        }
      }

      if (chosenWorkerId === -1) {
        // Fallback to round-robin
        chosenWorkerId = this.nextWorkerIndex % this.poolSize;
        this.nextWorkerIndex = (this.nextWorkerIndex + 1) % this.poolSize;
      }

      const taskId = `task_${++this.taskIdCounter}`;
      const worker = this.workers[chosenWorkerId];
      const stat = this.stats[chosenWorkerId];

      if (!worker || !stat) {
        return reject(new Error("No worker available in worker pool"));
      }

      stat.activeTasks++;
      this.pendingTasks.set(taskId, { resolve, reject });

      worker.postMessage({
        type: "PROCESS_BATCH",
        taskId,
        items,
      });
    });
  }

  getStats() {
    let totalProcessed = 0;
    let totalDedup = 0;
    let totalActive = 0;
    let sumAvgLatency = 0;
    let aliveWorkers = 0;

    const perWorker = this.stats.map((s) => {
      if (s.isAlive) aliveWorkers++;
      totalProcessed += s.processedCount;
      totalDedup += s.dedupHits;
      totalActive += s.activeTasks;
      sumAvgLatency += s.avgLatencyMs;
      return {
        workerId: s.workerId,
        isAlive: s.isAlive,
        processedCount: s.processedCount,
        activeTasks: s.activeTasks,
        avgLatencyMs: s.avgLatencyMs,
        dedupHits: s.dedupHits,
      };
    });

    return {
      poolSize: this.poolSize,
      aliveWorkers,
      totalProcessed,
      totalDedup,
      totalActiveTasks: totalActive,
      avgLatencyMs: aliveWorkers > 0 ? Number((sumAvgLatency / aliveWorkers).toFixed(3)) : 0,
      workers: perWorker,
    };
  }

  async shutdown() {
    for (const worker of this.workers) {
      if (worker) await worker.terminate();
    }
  }
}

module.exports = { WorkerPool };
