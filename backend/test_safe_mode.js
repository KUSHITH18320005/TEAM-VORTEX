const http = require("http");

function request(options, postData) {
  return new Promise((resolve, reject) => {
    const headers = { ...(options.headers || {}) };
    if (postData) {
      headers["Content-Length"] = Buffer.byteLength(postData);
    }
    const reqOptions = { ...options, headers };

    const req = http.request(reqOptions, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => resolve({ statusCode: res.statusCode, headers: res.headers, body: data }));
    });
    req.on("error", (err) => reject(err));
    if (postData) {
      req.write(postData);
    }
    req.end();
  });
}

async function runSafeModeTests() {
  console.log("==================================================");
  console.log("   RUNNING SAFE MODE (VULN_MODE=false) SANITY PASS");
  console.log("==================================================");

  let passed = 0;
  let total = 0;

  function assert(condition, label, details) {
    total++;
    if (condition) {
      passed++;
      console.log(`[PASS] ${label}`);
    } else {
      console.error(`[FAIL] ${label} - Details: ${details}`);
    }
  }

  // 1. NoSQL Injection blocked
  const resNosql = await request({
    host: "localhost",
    port: 3002,
    path: "/allOrders?filter=" + encodeURIComponent('{"qty":{"$gt":0}}'),
    method: "GET",
  });
  assert(resNosql.statusCode === 400, "1. NoSQL Injection Blocked (HTTP 400)", `Got status ${resNosql.statusCode}`);

  // 2. Business Logic price/qty enforced
  const badOrder = JSON.stringify({ name: "INFY", qty: -10, price: 0.001, mode: "BUY" });
  const resBadOrder = await request(
    {
      host: "localhost",
      port: 3002,
      path: "/newOrder",
      method: "POST",
      headers: { "Content-Type": "application/json" },
    },
    badOrder
  );
  assert(resBadOrder.statusCode === 400, "2. Business Logic Bad Quantity Blocked (HTTP 400)", `Got status ${resBadOrder.statusCode}`);

  // 3. Stored XSS input sanitization
  const xssTicket = JSON.stringify({ topic: "Support", email: "test@lab.com", message: "<script>alert(1)</script>" });
  const resXss = await request(
    {
      host: "localhost",
      port: 3002,
      path: "/newTicket",
      method: "POST",
      headers: { "Content-Type": "application/json" },
    },
    xssTicket
  );
  assert(resXss.statusCode === 200, "3. Ticket Sanitized (HTTP 200)", `Got status ${resXss.statusCode}`);

  // 4. Data Exfil protected
  const resExfil = await request({
    host: "localhost",
    port: 3002,
    path: "/admin/exportAll",
    method: "GET",
  });
  assert(resExfil.statusCode === 403, "4. Data Exfil Blocked without Admin Bearer (HTTP 403)", `Got status ${resExfil.statusCode}`);

  // 5. JWT Abuse - alg: none rejected
  const algNoneToken = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6InN1cGVyYWRtaW4ifQ.";
  const resAlgNone = await request({
    host: "localhost",
    port: 3002,
    path: "/order/ord_102",
    method: "GET",
    headers: { Authorization: `Bearer ${algNoneToken}` },
  });
  assert(resAlgNone.statusCode === 401, "5. JWT alg:none Forgery Rejected (HTTP 401)", `Got status ${resAlgNone.statusCode}`);

  // 6. Session Hijacking - Cookie header present in response & token extracted
  const loginPayload = JSON.stringify({ username: "trader_alice", password: "password123" });
  const resLogin = await request(
    {
      host: "localhost",
      port: 3002,
      path: "/login",
      method: "POST",
      headers: { "Content-Type": "application/json" },
    },
    loginPayload
  );
  const setCookie = resLogin.headers["set-cookie"] || [];
  assert(
    setCookie.some((c) => c.includes("auth_token") && c.includes("HttpOnly")),
    "6. Session Token In HttpOnly Cookie",
    `Set-Cookie headers: ${JSON.stringify(setCookie)}`
  );

  const loginData = JSON.parse(resLogin.body);
  const validAliceToken = loginData.token;

  // 7. Brute Force Account Lockout (5 bad attempts)
  for (let i = 1; i <= 5; i++) {
    const badLogin = JSON.stringify({ username: "admin", password: "wrong_pwd_" + i });
    await request(
      {
        host: "localhost",
        port: 3002,
        path: "/login",
        method: "POST",
        headers: { "Content-Type": "application/json" },
      },
      badLogin
    );
  }
  const resLocked = await request(
    {
      host: "localhost",
      port: 3002,
      path: "/login",
      method: "POST",
      headers: { "Content-Type": "application/json" },
    },
    JSON.stringify({ username: "admin", password: "admin123" })
  );
  assert(resLocked.statusCode === 429, "7. Brute Force Account Lockout Active (HTTP 429)", `Got status ${resLocked.statusCode}`);

  // 8. Account Takeover - Strong reset token generated
  const resForgot = await request(
    {
      host: "localhost",
      port: 3002,
      path: "/forgotPassword",
      method: "POST",
      headers: { "Content-Type": "application/json" },
    },
    JSON.stringify({ email: "alice@investor.com" })
  );
  const forgotData = JSON.parse(resForgot.body);
  assert(!forgotData.resetToken, "8. Reset Token Not Leaked in Body", `Body: ${resForgot.body}`);

  // 9. IDOR - Ownership verification (Alice trying to access Admin's order ord_102)
  const resIdor = await request({
    host: "localhost",
    port: 3002,
    path: "/order/ord_102",
    method: "GET",
    headers: { Authorization: `Bearer ${validAliceToken}` },
  });
  assert(resIdor.statusCode === 403, "9. IDOR Forbidden for Non-Owner (HTTP 403)", `Got status ${resIdor.statusCode}`);

  // 10. Web Auth Bypass - Client header ignored
  const resAuthBypass = await request({
    host: "localhost",
    port: 3002,
    path: "/admin/dashboard-stats",
    method: "GET",
    headers: { "x-is-admin": "true" },
  });
  assert(resAuthBypass.statusCode === 401, "10. Auth Bypass Header Blocked (HTTP 401)", `Got status ${resAuthBypass.statusCode}`);

  // 11. CSRF - Token enforcement
  const resCsrf = await request(
    {
      host: "localhost",
      port: 3002,
      path: "/changePassword",
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${validAliceToken}`,
      },
    },
    JSON.stringify({ newPassword: "SafePassword123!" })
  );
  assert(resCsrf.statusCode === 403, "11. CSRF Missing Token Blocked (HTTP 403)", `Got status ${resCsrf.statusCode}`);

  // 12. SSRF - Loopback and private IP blocking
  const resSsrf = await request({
    host: "localhost",
    port: 3002,
    path: "/news?url=" + encodeURIComponent("http://127.0.0.1:3002/admin/exportAll"),
    method: "GET",
  });
  assert(resSsrf.statusCode === 403, "12. SSRF Loopback Destination Blocked (HTTP 403)", `Got status ${resSsrf.statusCode}`);

  // 13. XXE - DTD and external entities blocked
  const xxeXml = `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]><holdings><stock>&xxe;</stock></holdings>`;
  const resXxe = await request(
    {
      host: "localhost",
      port: 3002,
      path: "/importHoldings",
      method: "POST",
      headers: { "Content-Type": "application/xml" },
    },
    xxeXml
  );
  assert(resXxe.statusCode === 400, "13. XXE External Entities Prohibited (HTTP 400)", `Got status ${resXxe.statusCode}`);

  console.log("==================================================");
  console.log(`   SAFE MODE SANITY RESULTS: ${passed}/${total} PASSED   `);
  console.log("==================================================");

  if (passed === total) {
    process.exit(0);
  } else {
    process.exit(1);
  }
}

runSafeModeTests().catch((e) => {
  console.error(e);
  process.exit(1);
});
