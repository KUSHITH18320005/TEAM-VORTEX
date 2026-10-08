const http = require("http");

function request(options, postData = null) {
  return new Promise((resolve, reject) => {
    const startTime = process.hrtime();
    const req = http.request(options, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => {
        const diff = process.hrtime(startTime);
        const latencyMs = Math.round(diff[0] * 1000 + diff[1] / 1000000);
        let parsed = data;
        try {
          parsed = JSON.parse(data);
        } catch (e) {}
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body: parsed,
          raw: data,
          latencyMs,
        });
      });
    });
    req.on("error", (err) => reject(err));
    if (postData) {
      req.write(typeof postData === "string" ? postData : JSON.stringify(postData));
    }
    req.end();
  });
}

async function runAll10Verification() {
  console.log("======================================================================");
  console.log("   AUTOMATED VERIFICATION SUITE: ATTACKS #1–10 (REAL-SITE PIPELINE)   ");
  console.log("======================================================================");

  const attacks = [
    { id: "nosql-injection", name: "NoSQL Query Operator Injection ($gt, $ne)" },
    { id: "xss-stored", name: "Stored Cross-Site Scripting (XSS)" },
    { id: "open-redirect", name: "Unvalidated URL Redirection" },
    { id: "business-logic", name: "Business Logic / Price & Quantity Tampering" },
    { id: "api-abuse", name: "API Abuse (Unbounded Collection Dump)" },
    { id: "no-rate-limit", name: "Missing Rate Limiting Burst (20 Rapid Requests)" },
    { id: "data-exfil", name: "Administrative Data Exfiltration (Unauthenticated Dump)" },
    { id: "jwt-abuse", name: "JWT Algorithm None / Signature Trust Abuse" },
    { id: "session-hijack", name: "Session Hijacking (LocalStorage Token Leak)" },
    { id: "session-fixation", name: "Session Identifier Fixation (Pre-Auth Reuse)" },
  ];

  let passed = 0;
  let failed = 0;

  for (let i = 0; i < attacks.length; i++) {
    const atk = attacks[i];
    console.log(`\n----------------------------------------------------------------------`);
    console.log(`[ATTACK #${i + 1}] Triggering: ${atk.name} (${atk.id})`);
    console.log(`----------------------------------------------------------------------`);

    try {
      const res = await request({
        host: "127.0.0.1",
        port: 3002,
        path: `/simulation/trigger/app/${atk.id}`,
        method: "POST",
      });

      console.log(`HTTP Status: ${res.statusCode} (${res.latencyMs}ms)`);
      if (res.statusCode === 200 && res.body?.success) {
        console.log(`Status: EXECUTED ✅`);
        console.log(`Exploit Banner: "${res.body.effectSummary?.exploitBanner || res.body.exploitBanner || "N/A"}"`);
        console.log(`Traces Emitted: ${res.body.traces?.length || 0}`);
        console.log(`Terminal Logs: ${res.body.terminalLogs?.length || 0}`);
        passed++;
      } else if (res.body?.status === "Blocked" || res.body?.vulnMode === false) {
        console.log(`Status: BLOCKED (Safe Mode Gated) 🛡️`);
        console.log(`Exploit Banner: "${res.body.effectSummary?.exploitBanner || res.body.exploitBanner || "N/A"}"`);
        passed++;
      } else {
        console.log(`Status: FAILED ❌ - Response:`, res.body);
        failed++;
      }
    } catch (err) {
      console.error(`Error executing ${atk.id}:`, err.message);
      failed++;
    }
  }

  console.log("\n======================================================================");
  console.log(`   TEST SUMMARY: ${passed}/${attacks.length} Passed, ${failed} Failed`);
  console.log("======================================================================");

  if (failed === 0) {
    console.log("🎉 ALL 10 REAL-SITE ATTACKS VERIFIED SUCCESSFULLY!");
  } else {
    process.exitCode = 1;
  }
}

runAll10Verification();
