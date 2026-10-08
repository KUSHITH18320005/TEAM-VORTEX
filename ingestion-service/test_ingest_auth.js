const http = require("http");
const jwt = require("jsonwebtoken");
const config = require("./config");
const { securityEventsBuffer } = require("./server");

const HOST = "127.0.0.1";
const PORT = config.PORT || 4000;
const SERVICE_TOKEN = config.INGEST_SERVICE_TOKEN;
const JWT_SECRET = config.JWT_SECRET;

function httpRequest(options, body = null) {
  return new Promise((resolve) => {
    const req = http.request(options, (res) => {
      let data = "";
      res.on("data", (c) => (data += c));
      res.on("end", () => {
        let parsed = null;
        try {
          parsed = JSON.parse(data);
        } catch (e) {
          parsed = data;
        }
        resolve({ status: res.statusCode, headers: res.headers, data: parsed });
      });
    });

    req.on("error", (err) => {
      resolve({ status: 0, error: err.message });
    });

    if (body) {
      req.write(typeof body === "string" ? body : JSON.stringify(body));
    }
    req.end();
  });
}

async function runAuthTests() {
  console.log("================================================================================");
  console.log("🔒 TESTING INGESTION SERVICE ACCESS CONTROL & PERMISSION TIERS");
  console.log("================================================================================");

  let passed = 0;
  let total = 0;

  function assert(name, condition, details = "") {
    total++;
    if (condition) {
      console.log(`[TEST ${total}] ${name.padEnd(58, " ")} ... ✅ PASSED`);
      passed++;
    } else {
      console.log(`[TEST ${total}] ${name.padEnd(58, " ")} ... ❌ FAILED (${details})`);
    }
  }

  // TEST 1: Unauthenticated single log ingress -> 401
  const res1 = await httpRequest({
    hostname: HOST,
    port: PORT,
    path: "/ingest/log",
    method: "POST",
    headers: { "Content-Type": "application/json" },
  }, { category: "nosql-injection", ip: "10.0.0.1" });
  assert("Unauthenticated /ingest/log rejected with 401", res1.status === 401 && res1.data?.code === "AUTH_TOKEN_MISSING", `status=${res1.status}`);

  // TEST 2: Invalid service token single log ingress -> 401
  const res2 = await httpRequest({
    hostname: HOST,
    port: PORT,
    path: "/ingest/log",
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": "Bearer totally_bogus_token_12345",
    },
  }, { category: "nosql-injection", ip: "10.0.0.1" });
  assert("Invalid Bearer token rejected with 401", res2.status === 401 && res2.data?.code === "AUTH_TOKEN_INVALID", `status=${res2.status}`);

  // TEST 3: Unauthenticated batch ingress -> 401
  const res3 = await httpRequest({
    hostname: HOST,
    port: PORT,
    path: "/ingest/batch",
    method: "POST",
    headers: { "Content-Type": "application/json" },
  }, [{ category: "ddos", ip: "192.168.1.1" }]);
  assert("Unauthenticated /ingest/batch rejected with 401", res3.status === 401, `status=${res3.status}`);

  // TEST 4: Authenticated single log ingress with valid service token -> 202 Accepted
  const res4 = await httpRequest({
    hostname: HOST,
    port: PORT,
    path: "/ingest/log",
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${SERVICE_TOKEN}`,
    },
  }, {
    category: "xss-stored",
    ip: "198.51.100.12",
    endpoint: "/api/comments",
    method: "POST",
    payload: { body: { comment: "<script>alert(1)</script>" } },
    source: "test-suite",
  });
  assert("Authenticated /ingest/log accepted with 202", res4.status === 202 && res4.data?.success === true && res4.data?.eventId, `status=${res4.status}`);

  // TEST 5: Authenticated batch ingress with valid service token -> 202 Accepted
  const res5 = await httpRequest({
    hostname: HOST,
    port: PORT,
    path: "/ingest/batch",
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${SERVICE_TOKEN}`,
    },
  }, [
    { category: "ddos", ip: "198.51.100.20", endpoint: "/orders", method: "GET" },
    { category: "botnet-c2", ip: "198.51.100.21", endpoint: "/beacon", method: "POST" },
  ]);
  assert("Authenticated /ingest/batch accepted with 202", res5.status === 202 && res5.data?.acceptedCount === 2, `status=${res5.status}`);

  // TEST 6: Admin endpoint without JWT -> 401
  const res6 = await httpRequest({
    hostname: HOST,
    port: PORT,
    path: "/ingest/admin/retry-failed",
    method: "POST",
    headers: { "Content-Type": "application/json" },
  });
  assert("Unauthenticated /ingest/admin/retry-failed -> 401", res6.status === 401, `status=${res6.status}`);

  // TEST 7: Admin endpoint with Non-Admin JWT (role: 'trader') -> 403 Forbidden
  const traderToken = jwt.sign({ id: "trader_001", role: "trader", username: "alice" }, JWT_SECRET, { expiresIn: "1h" });
  const res7 = await httpRequest({
    hostname: HOST,
    port: PORT,
    path: "/ingest/admin/retry-failed",
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${traderToken}`,
    },
  });
  assert("Non-admin JWT on admin endpoint -> 403 Forbidden", res7.status === 403, `status=${res7.status}`);

  // TEST 8: Admin endpoint with Real Admin JWT (role: 'admin') -> 200 OK
  const adminToken = jwt.sign({ id: "admin_001", role: "admin", username: "sysadmin" }, JWT_SECRET, { expiresIn: "1h" });
  const res8 = await httpRequest({
    hostname: HOST,
    port: PORT,
    path: "/ingest/admin/retry-failed",
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${adminToken}`,
    },
  });
  assert("Real Admin JWT on admin endpoint -> 200 OK", res8.status === 200 && res8.data?.success === true, `status=${res8.status}`);

  // TEST 9: Health probe -> 200
  const res9 = await httpRequest({
    hostname: HOST,
    port: PORT,
    path: "/health",
    method: "GET",
  });
  assert("Open /health probe returns 200 OK", res9.status === 200 && res9.data?.status === "ok", `status=${res9.status}`);

  // TEST 10: Ready probe -> 200 (Ready)
  const res10 = await httpRequest({
    hostname: HOST,
    port: PORT,
    path: "/ready",
    method: "GET",
  });
  assert("Open /ready probe returns 200 / 503 check", res10.status === 200 || res10.status === 503, `status=${res10.status}`);

  // TEST 11: Stats endpoint -> 200 with complete metrics snapshot
  const res11 = await httpRequest({
    hostname: HOST,
    port: PORT,
    path: "/ingest/stats",
    method: "GET",
  });
  const hasStatsFields = res11.data && res11.data.throughput && res11.data.workers && res11.data.circuitBreaker;
  assert("Open /ingest/stats returns complete metric snapshot", res11.status === 200 && hasStatsFields, `status=${res11.status}`);

  console.log("================================================================================");
  console.log(`🏁 AUTH & PERMISSION TEST RESULTS: ${passed}/${total} PASSED`);
  console.log("================================================================================\n");

  if (passed === total) {
    process.exit(0);
  } else {
    process.exit(1);
  }
}

if (require.main === module) {
  runAuthTests().catch((err) => {
    console.error("[TEST FAILED]", err);
    process.exit(1);
  });
}

module.exports = { runAuthTests };
