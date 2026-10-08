# @madps/agent

Official client integration SDK for **MAD-PS** (Multi-Agent Debate & Autonomous Attack Detection Platform).

Connects your Express / Node.js application to MAD-PS AI-Powered SOC in under 60 seconds.

## Installation

```bash
npm install @madps/agent
```

## Quickstart

```javascript
const express = require('express');
const madpsAgent = require('@madps/agent');

const app = express();

// Install MAD-PS Security Agent before application routes
app.use(madpsAgent({
  apiKey: process.env.MAD_PS_API_KEY || 'mk_live_your_live_key_here',
  endpoint: 'http://127.0.0.1:8000/api/v1/ingest/log'
}));

app.get('/api/v1/users', (req, res) => {
  res.json({ status: 'ok' });
});

app.listen(3000, () => {
  console.log('App running with MAD-PS active protection');
});
```

## Security & Compliance
- **Zero Token Leakage**: Sensitive headers (`Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`, `X-CSRF-Token`) are automatically redacted before transmission.
- **Fail-Safe Circuit Breaker**: If MAD-PS becomes unreachable, the SDK trips a circuit breaker and fails silently without adding latency or breaking your application.
- **Non-Blocking Telemetry**: Telemetry is dispatched asynchronously after the HTTP response stream is finished.
