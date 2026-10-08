/**
 * @madps/agent - MAD-PS Client Integration SDK for Express / Node.js
 * 
 * Non-blocking, circuit-broken telemetry forwarding middleware for MAD-PS AI-Powered SOC.
 * Sanitizes sensitive headers (cookies, auth tokens), captures request metadata,
 * and streams telemetry to the MAD-PS Ingestion Gateway.
 */

const http = require('http');
const https = require('https');
const url = require('url');

// Sensitive headers to strip before forwarding for client privacy & compliance
const DEFAULT_REDACTED_HEADERS = new Set([
  'authorization',
  'cookie',
  'set-cookie',
  'x-api-key',
  'proxy-authorization',
  'x-csrf-token',
  'x-xsrf-token',
  'session-token',
  'jwt',
]);

// Non-security static paths to skip by default
const DEFAULT_IGNORED_PATHS = new Set([
  '/health',
  '/healthz',
  '/favicon.ico',
  '/ping',
  '/demo/status',
  '/simulation/status',
  '/demo/events',
  '/simulation/trace-events',
  '/demo/ingest-stats',
]);

const DEFAULT_IGNORED_EXTENSIONS = /\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map)$/i;

class CircuitBreaker {
  constructor({ threshold = 50, resetTimeoutMs = 2000 } = {}) {
    this.threshold = threshold;
    this.resetTimeoutMs = resetTimeoutMs;
    this.failureCount = 0;
    this.isOpen = false;
    this.lastFailureTime = 0;
  }

  recordSuccess() {
    this.failureCount = 0;
    this.isOpen = false;
  }

  recordFailure() {
    this.failureCount++;
    this.lastFailureTime = Date.now();
    if (this.failureCount >= this.threshold) {
      this.isOpen = true;
    }
  }

  canAttempt() {
    if (!this.isOpen) return true;
    if (Date.now() - this.lastFailureTime >= this.resetTimeoutMs) {
      // Half-open: allow one retry attempt
      this.isOpen = false;
      this.failureCount = 0;
      return true;
    }
    return false;
  }
}

/**
 * Creates the MAD-PS Express Agent Middleware.
 * 
 * @param {Object} options
 * @param {string} options.apiKey - MAD-PS API Key (e.g. 'mk_live_...')
 * @param {string} [options.endpoint='http://127.0.0.1:8000/api/v1/ingest/log'] - Ingestion gateway URL
 * @param {number} [options.timeoutMs=1500] - Telemetry delivery timeout in milliseconds
 * @param {boolean} [options.debug=false] - Log debug messages
 * @param {Array<string|RegExp>} [options.excludePaths=[]] - Custom paths or regex to ignore
 * @param {Set<string>} [options.redactHeaders] - Set of lowercase header names to strip
 */
function madpsAgent(options = {}) {
  const apiKey = options.apiKey || process.env.MAD_PS_API_KEY;

  if (!apiKey) {
    console.warn('[MAD-PS SDK] Warning: No apiKey provided to madpsAgent. Telemetry will be disabled.');
  }

  const endpoint = options.endpoint || process.env.MAD_PS_INGEST_URL || 'http://127.0.0.1:8000/api/v1/ingest/log';
  const timeoutMs = options.timeoutMs || 5000;
  const debug = Boolean(options.debug);
  const excludePaths = options.excludePaths || [];
  const redactedHeaders = options.redactHeaders || DEFAULT_REDACTED_HEADERS;
  const breaker = new CircuitBreaker({
    threshold: options.circuitBreakerThreshold || 50,
    resetTimeoutMs: options.circuitBreakerResetMs || 2000,
  });

  const parsedUrl = url.parse(endpoint);
  const clientLib = parsedUrl.protocol === 'https:' ? https : http;

  function sanitizeHeaders(reqHeaders) {
    const clean = {};
    for (const [key, value] of Object.entries(reqHeaders || {})) {
      const lowerKey = key.toLowerCase();
      if (!redactedHeaders.has(lowerKey)) {
        clean[lowerKey] = value;
      }
    }
    return clean;
  }

  function shouldSkip(reqPath) {
    if (DEFAULT_IGNORED_PATHS.has(reqPath)) return true;
    if (reqPath.startsWith('/simulation/trigger')) return true;
    if (reqPath.startsWith('/simulation/theater')) return true;
    if (DEFAULT_IGNORED_EXTENSIONS.test(reqPath)) return true;
    for (const rule of excludePaths) {
      if (typeof rule === 'string' && reqPath === rule) return true;
      if (rule instanceof RegExp && rule.test(reqPath)) return true;
    }
    return false;
  }

  function postTraceStep(tracePayload) {
    try {
      const dataStr = JSON.stringify(tracePayload);
      const traceReqOpts = {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
        path: '/api/v1/pipeline/trace',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(dataStr),
        },
        timeout: 1000,
      };
      const treq = clientLib.request(traceReqOpts, (tres) => { tres.resume(); });
      treq.on('error', () => {});
      treq.on('timeout', () => treq.destroy());
      treq.write(dataStr);
      treq.end();
    } catch (e) {}
  }

  function forwardTelemetry(eventData) {
    if (!apiKey || !breaker.canAttempt()) {
      return;
    }

    const traceId = eventData.trace_id || ('trc_' + Date.now() + '_' + Math.random().toString(36).substring(2, 8));
    const isDebug = process.env.PIPELINE_DEBUG === 'true' || debug;
    const maskedKey = apiKey ? ('...' + apiKey.slice(-6)) : 'NONE';

    // Hop 1: [Z-SDK]
    if (isDebug) {
      console.log(`[PIPELINE_TRACE] Step 01 [Z-SDK]              | trace_id=${traceId} | service=zerodha-agent-sdk | route=${eventData.method} ${eventData.path} | key=${maskedKey}`);
    }
    postTraceStep({
      trace_id: traceId,
      hop_step: 1,
      hop_code: '[Z-SDK]',
      service: 'zerodha-agent-sdk',
      details: {
        route: `${eventData.method} ${eventData.path}`,
        category: eventData.category || 'unknown',
        apiKeyLast6: maskedKey,
        timestamp: eventData.timestamp,
        status_code: eventData.status_code,
      }
    });

    const sendStartTime = Date.now();

    try {
      const payloadString = JSON.stringify({ ...eventData, trace_id: traceId });
      const reqOpts = {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
        path: parsedUrl.path || '/api/v1/ingest/log',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payloadString),
          'X-API-Key': apiKey,
          'X-Trace-Id': traceId,
          'User-Agent': '@madps/agent-node/1.0.0',
        },
        timeout: timeoutMs,
      };

      const req = clientLib.request(reqOpts, (res) => {
        const latencyMs = Date.now() - sendStartTime;
        if (res.statusCode >= 200 && res.statusCode < 300) {
          breaker.recordSuccess();
          if (debug) console.log(`[MAD-PS SDK] Telemetry dispatched: ${eventData.method} ${eventData.path} (${res.statusCode})`);
        } else {
          breaker.recordFailure();
          if (debug) console.warn(`[MAD-PS SDK] Ingestion returned status: ${res.statusCode}`);
        }

        // Hop 2: [Z-SDK-SEND]
        if (isDebug) {
          console.log(`[PIPELINE_TRACE] Step 02 [Z-SDK-SEND]         | trace_id=${traceId} | service=zerodha-agent-sdk | status=${res.statusCode} | latency=${latencyMs}ms`);
        }
        postTraceStep({
          trace_id: traceId,
          hop_step: 2,
          hop_code: '[Z-SDK-SEND]',
          service: 'zerodha-agent-sdk',
          details: {
            success: res.statusCode >= 200 && res.statusCode < 300,
            status_code: res.statusCode,
            latency_ms: latencyMs,
          }
        });

        res.resume(); // Drain stream to free socket
      });

      req.on('error', (err) => {
        const latencyMs = Date.now() - sendStartTime;
        breaker.recordFailure();
        if (debug) console.warn(`[MAD-PS SDK] Telemetry dispatch failed: ${err.message}`);

        // Hop 2: [Z-SDK-SEND] (Error)
        if (isDebug) {
          console.log(`[PIPELINE_TRACE] Step 02 [Z-SDK-SEND]         | trace_id=${traceId} | service=zerodha-agent-sdk | FAILED: ${err.message}`);
        }
        postTraceStep({
          trace_id: traceId,
          hop_step: 2,
          hop_code: '[Z-SDK-SEND]',
          service: 'zerodha-agent-sdk',
          details: {
            success: false,
            status_code: 0,
            error: err.message,
            latency_ms: latencyMs,
          }
        });
      });

      req.on('timeout', () => {
        req.destroy();
        breaker.recordFailure();
        if (debug) console.warn('[MAD-PS SDK] Telemetry dispatch timed out');

        // Hop 2: [Z-SDK-SEND] (Timeout)
        postTraceStep({
          trace_id: traceId,
          hop_step: 2,
          hop_code: '[Z-SDK-SEND]',
          service: 'zerodha-agent-sdk',
          details: {
            success: false,
            status_code: 408,
            error: 'Telemetry dispatch timed out',
          }
        });
      });

      req.write(payloadString);
      req.end();
    } catch (err) {
      breaker.recordFailure();
      if (debug) console.warn(`[MAD-PS SDK] Exception forwarding telemetry: ${err.message}`);
      postTraceStep({
        trace_id: traceId,
        hop_step: 2,
        hop_code: '[Z-SDK-SEND]',
        service: 'zerodha-agent-sdk',
        details: {
          success: false,
          status_code: 500,
          error: err.message,
        }
      });
    }
  }

  return function madpsMiddleware(req, res, next) {
    const startTime = process.hrtime();
    const reqPath = req.path || (url.parse(req.url).pathname);

    // Fast path: skip static files and ignored endpoints
    if (shouldSkip(reqPath)) {
      return next();
    }

    // Capture payload preview if available
    let bodyPreview = '';
    if (req.body) {
      try {
        bodyPreview = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
        if (bodyPreview.length > 2048) {
          bodyPreview = bodyPreview.substring(0, 2048) + '...[truncated]';
        }
      } catch {
        bodyPreview = '[unserializable body]';
      }
    }

    const clientIp = req.headers['x-forwarded-for'] || req.socket?.remoteAddress || req.ip || '127.0.0.1';
    const incomingTraceId = req.headers['x-trace-id'] || ('trc_' + Date.now() + '_' + Math.random().toString(36).substring(2, 8));

    // Attach trace_id to request object so downstream route handlers can log or trace it
    req.traceId = incomingTraceId;

    // Hook into response finish event for non-blocking asynchronous forwarding
    res.on('finish', () => {
      const diff = process.hrtime(startTime);
      const latencyMs = (diff[0] * 1e3 + diff[1] * 1e-6).toFixed(2);

      const eventData = {
        trace_id: incomingTraceId,
        timestamp: new Date().toISOString(),
        method: req.method,
        path: reqPath,
        category: req.logCategory || 'general',
        query: req.query || {},
        headers: sanitizeHeaders(req.headers),
        payload: bodyPreview,
        status_code: res.statusCode,
        latency_ms: parseFloat(latencyMs),
        client_ip: Array.isArray(clientIp) ? clientIp[0] : clientIp.split(',')[0].trim(),
        sdk_version: '@madps/agent@1.0.0',
      };

      // Asynchronous dispatch outside of request loop
      setImmediate(() => forwardTelemetry(eventData));
    });

    next();
  };
}

module.exports = madpsAgent;
module.exports.madpsAgent = madpsAgent;
module.exports.CircuitBreaker = CircuitBreaker;
