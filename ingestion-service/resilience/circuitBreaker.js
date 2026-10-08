const { EventEmitter } = require("events");
const config = require("../config");

class CircuitBreaker extends EventEmitter {
  constructor(
    failThreshold = config.CIRCUIT_BREAKER_FAIL_THRESHOLD,
    cooldownMs = config.CIRCUIT_BREAKER_COOLDOWN_MS
  ) {
    super();
    this.failThreshold = failThreshold;
    this.cooldownMs = cooldownMs;

    this.state = "CLOSED"; // CLOSED, OPEN, HALF-OPEN
    this.consecutiveFailures = 0;
    this.consecutiveSuccesses = 0;
    this.totalTrips = 0;
    this.lastFailureTime = null;
    this.lastStateChange = new Date().toISOString();
  }

  canExecute() {
    if (this.state === "CLOSED") {
      return true;
    }

    if (this.state === "OPEN") {
      const now = Date.now();
      if (this.lastFailureTime && now - this.lastFailureTime >= this.cooldownMs) {
        this.transitionTo("HALF-OPEN");
        return true;
      }
      return false;
    }

    if (this.state === "HALF-OPEN") {
      return true;
    }

    return true;
  }

  recordSuccess() {
    this.consecutiveFailures = 0;
    this.consecutiveSuccesses++;

    if (this.state === "HALF-OPEN" || this.state === "OPEN") {
      console.log(`[CIRCUIT_BREAKER_CLOSED] Database connection restored. Resuming direct batch writes.`);
      this.transitionTo("CLOSED");
    }
  }

  recordFailure(error) {
    this.consecutiveFailures++;
    this.consecutiveSuccesses = 0;
    this.lastFailureTime = Date.now();

    if (this.state === "HALF-OPEN") {
      console.warn(`[CIRCUIT_BREAKER_OPEN] Trial write in HALF-OPEN failed (${error?.message || "Unknown error"}). Re-opening circuit.`);
      this.transitionTo("OPEN");
      return;
    }

    if (this.state === "CLOSED" && this.consecutiveFailures >= this.failThreshold) {
      console.warn(`[CIRCUIT_BREAKER_OPEN] ${this.consecutiveFailures} consecutive MongoDB write failures. Tripping circuit breaker to OPEN state. Cooldown: ${this.cooldownMs / 1000}s.`);
      this.totalTrips++;
      this.transitionTo("OPEN");
    }
  }

  transitionTo(newState) {
    const oldState = this.state;
    this.state = newState;
    this.lastStateChange = new Date().toISOString();
    this.emit("state_change", { from: oldState, to: newState, timestamp: this.lastStateChange });
  }

  getStats() {
    return {
      state: this.state,
      isOpen: this.state === "OPEN",
      isHalfOpen: this.state === "HALF-OPEN",
      isClosed: this.state === "CLOSED",
      consecutiveFailures: this.consecutiveFailures,
      failureThreshold: this.failThreshold,
      totalTrips: this.totalTrips,
      lastFailureTime: this.lastFailureTime ? new Date(this.lastFailureTime).toISOString() : null,
      lastStateChange: this.lastStateChange,
    };
  }
}

module.exports = { CircuitBreaker };
