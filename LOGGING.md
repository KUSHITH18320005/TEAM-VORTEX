# MAD-PS Detection Pipeline — Log Ingestion Specification (`LOGGING.md`)

This document defines the structured log schema emitted by the Zerodha-clone target application. It is the formal specification for downstream Security Information and Event Management (SIEM), anomaly detection engines, and the **MAD-PS Detection Pipeline**.

---

## 1. Storage & Ingestion Channels

Security event telemetry is delivered simultaneously via two parallel channels:
1. **stdout**: Emitted as single-line JSON strings to standard output, suitable for log collectors (Fluentbit, Vector, Logstash, Datadog Agent).
2. **MongoDB `logs` Collection**: Persisted directly to the `logs` collection within the target MongoDB database (`LogModel` / `LogSchema`).

---

## 2. Structured Log Schema

Every recorded event adheres strictly to the following JSON schema:

| Field Name | Type | Description |
|------------|------|-------------|
| `timestamp` | `String` (ISO 8601) / `Date` | Timestamp of when the request was received by the server. |
| `ip` | `String` | Client source IP address (resolved via `x-forwarded-for`, `req.ip`, or socket). |
| `endpoint` | `String` | Full original URL path including query strings (e.g. `/allOrders?filter=...`). |
| `method` | `String` | HTTP request method (`GET`, `POST`, `PUT`, `DELETE`). |
| `payload` | `Object` | Request body, parsed query parameters, and route parameters: `{ body: Object, query: Object, params: Object }`. |
| `category` | `String` | Normalized attack classification tag (1 of 19 categories or general). |

---

## 3. Complete Category Inventory (19 Categories)

The `category` field contains one of the following 19 recognized attack classification strings:

### Phase 1 Categories (7)
1. `nosql-injection` — MongoDB operator injection via query filters.
2. `xss-stored` — Unsanitized HTML/JS payloads stored in database/models.
3. `open-redirect` — External redirection via URL parameters.
4. `business-logic` — Negative quantity, sub-penny pricing, and balance tampering.
5. `api-abuse` — Unbounded result sets, missing pagination, and 50MB payload limits.
6. `no-rate-limit` — Unthrottled request bursts.
7. `data-exfil` — Unauthenticated bulk database exfiltration.

### Phase 2 Categories (12)
8. `jwt-abuse` — `alg: none` unsigned tokens and weak signing keys.
9. `session-hijack` — Session tokens exposed to client-side scripts via `localStorage`.
10. `session-fixation` — Session ID reuse across unauthenticated and authenticated states.
11. `bruteforce` — High-frequency password attempts on single user account without lockout.
12. `credential-stuffing` — Multi-username credential attempts from single IP address.
13. `password-spraying` — Single password tested across multiple distinct user accounts.
14. `account-takeover` — Predictable/low-entropy password reset tokens without expiration.
15. `idor` — Insecure Direct Object Reference on order and portfolio IDs.
16. `auth-bypass` — Privilege escalation and auth gating via client headers (`x-is-admin: true`).
17. `csrf` — State changes performed without Anti-CSRF token verification.
18. `ssrf` — Server-side fetching of arbitrary internal or cloud metadata URLs.
19. `xxe` — XML External Entity resolution against server files or network URIs.

---

## 4. Full JSON Log Examples for All 19 Categories

### 1. `nosql-injection`
```json
{
  "timestamp": "2026-08-15T12:50:54.834Z",
  "ip": "::1",
  "endpoint": "/allOrders?filter=%7B%22qty%22%3A%7B%22%24gt%22%3A0%7D%7D",
  "method": "GET",
  "payload": {
    "body": {},
    "query": { "filter": "{\"qty\":{\"$gt\":0}}" },
    "params": {}
  },
  "category": "nosql-injection"
}
```

### 2. `xss-stored`
```json
{
  "timestamp": "2026-08-15T12:50:54.845Z",
  "ip": "::1",
  "endpoint": "/newTicket",
  "method": "POST",
  "payload": {
    "body": {
      "topic": "Account Security",
      "email": "tester@security.lab",
      "message": "<script>alert('XSS_TICKET')</script>"
    },
    "query": {},
    "params": {}
  },
  "category": "xss-stored"
}
```

### 3. `open-redirect`
```json
{
  "timestamp": "2026-08-15T12:34:56.789Z",
  "ip": "::1",
  "endpoint": "/?redirect=https://evil-phishing-target.com",
  "method": "GET",
  "payload": {
    "body": {},
    "query": { "redirect": "https://evil-phishing-target.com" },
    "params": {}
  },
  "category": "open-redirect"
}
```

### 4. `business-logic`
```json
{
  "timestamp": "2026-08-15T12:50:54.840Z",
  "ip": "::1",
  "endpoint": "/newOrder",
  "method": "POST",
  "payload": {
    "body": {
      "name": "RELIANCE",
      "qty": -100,
      "price": 0.001,
      "mode": "BUY",
      "notes": "Tampered trade"
    },
    "query": {},
    "params": {}
  },
  "category": "business-logic"
}
```

### 5. `api-abuse`
```json
{
  "timestamp": "2026-08-15T12:50:54.823Z",
  "ip": "::1",
  "endpoint": "/allHoldings",
  "method": "GET",
  "payload": {
    "body": {},
    "query": {},
    "params": {}
  },
  "category": "api-abuse"
}
```

### 6. `no-rate-limit`
```json
{
  "timestamp": "2026-08-15T12:35:52.636Z",
  "ip": "::1",
  "endpoint": "/allOrders",
  "method": "GET",
  "payload": {
    "body": {},
    "query": {},
    "params": {}
  },
  "category": "no-rate-limit"
}
```

### 7. `data-exfil`
```json
{
  "timestamp": "2026-08-15T12:50:49.435Z",
  "ip": "::1",
  "endpoint": "/admin/exportAll",
  "method": "GET",
  "payload": {
    "body": {},
    "query": {},
    "params": {}
  },
  "category": "data-exfil"
}
```

### 8. `jwt-abuse`
```json
{
  "timestamp": "2026-08-15T12:50:48.253Z",
  "ip": "::1",
  "endpoint": "/order/ord_102",
  "method": "GET",
  "payload": {
    "body": {},
    "query": {},
    "params": {}
  },
  "category": "jwt-abuse"
}
```

### 9. `session-hijack`
```json
{
  "timestamp": "2026-08-15T12:50:48.141Z",
  "ip": "::1",
  "endpoint": "/login",
  "method": "POST",
  "payload": {
    "body": {
      "username": "trader_alice",
      "password": "password123"
    },
    "query": {},
    "params": {}
  },
  "category": "session-hijack"
}
```

### 10. `session-fixation`
```json
{
  "timestamp": "2026-08-15T12:50:48.258Z",
  "ip": "::1",
  "endpoint": "/login",
  "method": "POST",
  "payload": {
    "body": {
      "username": "trader_alice",
      "password": "password123"
    },
    "query": {},
    "params": {}
  },
  "category": "session-fixation"
}
```

### 11. `bruteforce`
```json
{
  "timestamp": "2026-08-15T12:50:48.483Z",
  "ip": "::1",
  "endpoint": "/login",
  "method": "POST",
  "payload": {
    "username": "admin",
    "failedAttemptCount": 3
  },
  "category": "bruteforce"
}
```

### 12. `credential-stuffing`
```json
{
  "timestamp": "2026-08-15T12:50:49.067Z",
  "ip": "::1",
  "endpoint": "/login",
  "method": "POST",
  "payload": {
    "username": "user_beta",
    "failedAttemptCount": 1
  },
  "category": "credential-stuffing"
}
```

### 13. `password-spraying`
```json
{
  "timestamp": "2026-08-15T12:50:49.065Z",
  "ip": "::1",
  "endpoint": "/login",
  "method": "POST",
  "payload": {
    "username": "user_alpha",
    "failedAttemptCount": 1
  },
  "category": "password-spraying"
}
```

### 14. `account-takeover`
```json
{
  "timestamp": "2026-08-15T12:50:49.188Z",
  "ip": "::1",
  "endpoint": "/forgotPassword",
  "method": "POST",
  "payload": {
    "body": {
      "email": "alice@investor.com"
    },
    "query": {},
    "params": {}
  },
  "category": "account-takeover"
}
```

### 15. `idor`
```json
{
  "timestamp": "2026-08-15T12:50:49.301Z",
  "ip": "::1",
  "endpoint": "/order/ord_102",
  "method": "GET",
  "payload": {
    "body": {},
    "query": {},
    "params": {}
  },
  "category": "idor"
}
```

### 16. `auth-bypass`
```json
{
  "timestamp": "2026-08-15T12:50:49.305Z",
  "ip": "::1",
  "endpoint": "/admin/dashboard-stats",
  "method": "GET",
  "payload": {
    "body": {},
    "query": {},
    "params": {}
  },
  "category": "auth-bypass"
}
```

### 17. `csrf`
```json
{
  "timestamp": "2026-08-15T12:50:49.308Z",
  "ip": "::1",
  "endpoint": "/changePassword",
  "method": "POST",
  "payload": {
    "body": {
      "newPassword": "csrf_victim_pass"
    },
    "query": {},
    "params": {}
  },
  "category": "csrf"
}
```

### 18. `ssrf`
```json
{
  "timestamp": "2026-08-15T12:50:49.425Z",
  "ip": "::1",
  "endpoint": "/news?url=http://localhost:3002/admin/exportAll",
  "method": "GET",
  "payload": {
    "body": {},
    "query": {
      "url": "http://localhost:3002/admin/exportAll"
    },
    "params": {}
  },
  "category": "ssrf"
}
```

### 19. `xxe`
```json
{
  "timestamp": "2026-08-15T12:50:49.440Z",
  "ip": "::1",
  "endpoint": "/importHoldings",
  "method": "POST",
  "payload": {
    "body": {
      "raw": "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///C:/Windows/win.ini\">]><holdings><stock>&xxe;</stock></holdings>"
    },
    "query": {},
    "params": {}
  },
  "category": "xxe"
}
```
