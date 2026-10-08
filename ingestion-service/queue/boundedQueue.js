const { EventEmitter } = require("events");
const config = require("../config");

class BoundedQueue extends EventEmitter {
  constructor(maxSize = config.QUEUE_MAX_SIZE, backpressureRatio = config.QUEUE_BACKPRESSURE_RATIO) {
    super();
    this.maxSize = maxSize;
    this.backpressureThreshold = Math.floor(maxSize * backpressureRatio);
    this.items = [];
    this.head = 0; // Ring/pointer offset for high performance without Array.shift() O(N) penalty
    this.highWaterMark = 0;
    this.backpressureEngagedCount = 0;
    this.isCurrentlyBackpressured = false;
  }

  /**
   * Current active queue length
   */
  get length() {
    return this.items.length - this.head;
  }

  /**
   * Checks if backpressure is engaged
   */
  isBackpressured() {
    return this.length >= this.backpressureThreshold;
  }

  /**
   * Enqueue a single item if capacity allows
   * Returns { success: true } or { success: false, reason: "BACKPRESSURE_ENGAGED", retryAfter: 2 }
   */
  enqueue(item) {
    if (this.isBackpressured()) {
      if (!this.isCurrentlyBackpressured) {
        this.isCurrentlyBackpressured = true;
        this.backpressureEngagedCount++;
        console.warn(`[BACKPRESSURE_ENGAGED] Queue reached capacity threshold (${this.length}/${this.maxSize}). Shedding load.`);
        this.emit("backpressure", { depth: this.length, maxSize: this.maxSize });
      }
      return {
        success: false,
        reason: "BACKPRESSURE_ENGAGED",
        retryAfter: 2,
        currentDepth: this.length,
        maxSize: this.maxSize,
      };
    }

    if (this.isCurrentlyBackpressured && this.length < this.backpressureThreshold * 0.7) {
      this.isCurrentlyBackpressured = false;
      console.log(`[BACKPRESSURE_DISENGAGED] Queue depth recovered to ${this.length}/${this.maxSize}.`);
      this.emit("backpressure_relieved", { depth: this.length });
    }

    this.items.push(item);
    if (this.length > this.highWaterMark) {
      this.highWaterMark = this.length;
    }

    this.emit("item_enqueued");
    return { success: true, currentDepth: this.length };
  }

  /**
   * Enqueue a batch of items
   */
  enqueueBatch(items) {
    if (this.length + items.length > this.maxSize || this.isBackpressured()) {
      if (!this.isCurrentlyBackpressured) {
        this.isCurrentlyBackpressured = true;
        this.backpressureEngagedCount++;
        console.warn(`[BACKPRESSURE_ENGAGED] Queue rejecting batch of ${items.length} (Depth: ${this.length}/${this.maxSize}).`);
        this.emit("backpressure", { depth: this.length, maxSize: this.maxSize });
      }
      return {
        success: false,
        reason: "BACKPRESSURE_ENGAGED",
        retryAfter: 2,
        currentDepth: this.length,
        maxSize: this.maxSize,
      };
    }

    for (let i = 0; i < items.length; i++) {
      this.items.push(items[i]);
    }

    if (this.length > this.highWaterMark) {
      this.highWaterMark = this.length;
    }

    this.emit("items_enqueued", items.length);
    return { success: true, enqueuedCount: items.length, currentDepth: this.length };
  }

  /**
   * Dequeue up to `maxItems`
   */
  dequeueBatch(maxItems = 100) {
    if (this.head >= this.items.length) {
      this.items = [];
      this.head = 0;
      return [];
    }

    const available = this.items.length - this.head;
    const count = Math.min(available, maxItems);
    const result = this.items.slice(this.head, this.head + count);
    this.head += count;

    // Reset array if empty or head is large to free memory
    if (this.head >= this.items.length) {
      this.items = [];
      this.head = 0;
    } else if (this.head > 10000 && this.head > this.items.length / 2) {
      this.items = this.items.slice(this.head);
      this.head = 0;
    }

    return result;
  }

  /**
   * Dequeue a single item
   */
  dequeue() {
    if (this.head >= this.items.length) {
      this.items = [];
      this.head = 0;
      return null;
    }
    const item = this.items[this.head++];
    if (this.head >= this.items.length) {
      this.items = [];
      this.head = 0;
    }
    return item;
  }

  getStats() {
    return {
      currentDepth: this.length,
      maxSize: this.maxSize,
      backpressureThreshold: this.backpressureThreshold,
      isBackpressured: this.isCurrentlyBackpressured,
      highWaterMark: this.highWaterMark,
      backpressureEngagedCount: this.backpressureEngagedCount,
    };
  }
}

module.exports = { BoundedQueue };
