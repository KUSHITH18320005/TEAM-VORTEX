const http = require("http");

function makeRequest(options, postData) {
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => {
        try {
          resolve({ status: res.statusCode, headers: res.headers, data: JSON.parse(data) });
        } catch (e) {
          resolve({ status: res.statusCode, headers: res.headers, data });
        }
      });
    });
    req.on("error", (err) => reject(err));
    if (postData) {
      req.write(typeof postData === "string" ? postData : JSON.stringify(postData));
    }
    req.end();
  });
}

async function runComprehensiveAll30Test() {
  console.log("================================================================================");
  console.log("🔥 TESTING FULL 30-ATTACK SYSTEM (#1–30)");
  console.log("================================================================================");

  const attacks = [
    // Attacks #1–10 (Phase 1)
    { num: 1, cat: "nosql-injection", type: "REAL_BROWSER_PW" },
    { num: 2, cat: "xss-stored", type: "REAL_BROWSER_PW" },
    { num: 3, cat: "open-redirect", type: "REAL_BROWSER_PW" },
    { num: 4, cat: "business-logic", type: "REAL_BROWSER_PW" },
    { num: 5, cat: "api-abuse", type: "REAL_BROWSER_PW" },
    { num: 6, cat: "no-rate-limit", type: "REAL_BROWSER_PW" },
    { num: 7, cat: "data-exfil", type: "REAL_BROWSER_PW" },
    { num: 8, cat: "jwt-abuse", type: "REAL_BROWSER_PW" },
    { num: 9, cat: "session-hijack", type: "REAL_BROWSER_PW" },
    { num: 10, cat: "session-fixation", type: "REAL_BROWSER_PW" },

    // Attacks #11–20 (Phase 2)
    { num: 11, cat: "bruteforce", type: "REAL_BROWSER_PW" },
    { num: 12, cat: "credential-stuffing", type: "REAL_BROWSER_PW" },
    { num: 13, cat: "password-spraying", type: "REAL_BROWSER_PW" },
    { num: 14, cat: "account-takeover", type: "REAL_BROWSER_PW" },
    { num: 15, cat: "idor", type: "REAL_BROWSER_PW" },
    { num: 16, cat: "auth-bypass", type: "REAL_BROWSER_PW" },
    { num: 17, cat: "csrf", type: "REAL_BROWSER_PW" },
    { num: 18, cat: "ssrf", type: "REAL_BROWSER_PW" },
    { num: 19, cat: "xxe", type: "REAL_BROWSER_PW" },
    { num: 20, cat: "port-scanning-recon", type: "REAL_BROWSER_PW" },

    // Attacks #21–30 (Phase 3)
    { num: 21, cat: "network-service-enumeration", type: "REAL_TOOL_NMAP" },
    { num: 22, cat: "dos", type: "REAL_TOOL_LOAD" },
    { num: 23, cat: "ddos", type: "STAGED_THEATER" },
    { num: 24, cat: "dns-spoofing", type: "STAGED_THEATER" },
    { num: 25, cat: "mitm", type: "STAGED_THEATER" },
    { num: 26, cat: "ransomware-behavioral", type: "STAGED_THEATER" },
    { num: 27, cat: "trojan-behavioral", type: "STAGED_THEATER" },
    { num: 28, cat: "spyware-behavioral", type: "STAGED_THEATER" },
    { num: 29, cat: "botnet-c2", type: "STAGED_THEATER" },
    { num: 30, cat: "compromised-iot", type: "STAGED_THEATER" },
  ];

  let passed = 0;
  let failed = 0;

  for (const att of attacks) {
    const route = att.type === "STAGED_THEATER"
      ? `/simulation/trigger/theater/${att.cat}`
      : `/simulation/trigger/app/${att.cat}`;

    process.stdout.write(`[${att.num.toString().padStart(2, "0")}/30] ${att.cat.padEnd(30, " ")} [${att.type.padEnd(16, " ")}] ... `);

    try {
      const res = await makeRequest({
        host: "localhost",
        port: 3002,
        path: route,
        method: "POST",
        headers: { "Content-Type": "application/json" },
      }, { category: att.cat });

      if (res.status === 200 && res.data?.success) {
        console.log("✅ OK");
        passed++;
      } else {
        console.log(`❌ FAILED (${res.status})`);
        failed++;
      }
    } catch (err) {
      console.log(`❌ ERROR: ${err.message}`);
      failed++;
    }
  }

  console.log("================================================================================");
  console.log(`🏁 COMPREHENSIVE SUITE RESULTS: ${passed}/30 PASSED | ${failed} FAILED`);
  console.log("================================================================================");

  if (failed > 0) process.exit(1);
}

runComprehensiveAll30Test();
