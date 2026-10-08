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

async function runAll37AttacksTest() {
  console.log("================================================================================");
  console.log("🔥 TESTING FULL 37-ATTACK SUITE (#1–37) ACROSS ALL 4 TIERS");
  console.log("================================================================================");

  const attacks = [
    // Tier 1: Frontend & Client-Side (#1–5)
    { num: 1, cat: "xss-stored", tier: "Frontend", real: true, type: "REAL_BROWSER_PW" },
    { num: 2, cat: "session-hijack", tier: "Frontend", real: true, type: "REAL_BROWSER_PW" },
    { num: 3, cat: "csrf", tier: "Frontend", real: true, type: "REAL_BROWSER_PW" },
    { num: 4, cat: "open-redirect", tier: "Frontend", real: true, type: "REAL_BROWSER_PW" },
    { num: 5, cat: "auth-bypass", tier: "Frontend", real: true, type: "REAL_BROWSER_PW" },

    // Tier 2: Backend API & Auth (#6–16)
    { num: 6, cat: "business-logic", tier: "Backend", real: true, type: "REAL_BROWSER_PW" },
    { num: 7, cat: "no-rate-limit", tier: "Backend", real: true, type: "REAL_BROWSER_PW" },
    { num: 8, cat: "jwt-abuse", tier: "Backend", real: true, type: "REAL_BROWSER_PW" },
    { num: 9, cat: "session-fixation", tier: "Backend", real: true, type: "REAL_BROWSER_PW" },
    { num: 10, cat: "bruteforce", tier: "Backend", real: true, type: "REAL_BROWSER_PW" },
    { num: 11, cat: "credential-stuffing", tier: "Backend", real: true, type: "REAL_BROWSER_PW" },
    { num: 12, cat: "password-spraying", tier: "Backend", real: true, type: "REAL_BROWSER_PW" },
    { num: 13, cat: "account-takeover", tier: "Backend", real: true, type: "REAL_BROWSER_PW" },
    { num: 14, cat: "idor", tier: "Backend", real: true, type: "REAL_BROWSER_PW" },
    { num: 15, cat: "ssrf", tier: "Backend", real: true, type: "REAL_BROWSER_PW" },
    { num: 16, cat: "xxe", tier: "Backend", real: true, type: "REAL_BROWSER_PW" },

    // Tier 3: DBMS & Storage (#17–19)
    { num: 17, cat: "nosql-injection", tier: "DBMS", real: true, type: "REAL_BROWSER_PW" },
    { num: 18, cat: "api-abuse", tier: "DBMS", real: true, type: "REAL_BROWSER_PW" },
    { num: 19, cat: "data-exfil", tier: "DBMS", real: true, type: "REAL_BROWSER_PW" },

    // Tier 4: Network, OS & Advanced Threats (#20–37)
    { num: 20, cat: "port-scanning-recon", tier: "Network", real: true, type: "REAL_TOOL_PORT" },
    { num: 21, cat: "network-service-enumeration", tier: "Network", real: true, type: "REAL_TOOL_NMAP" },
    { num: 22, cat: "dos", tier: "Network", real: true, type: "REAL_TOOL_LOAD" },
    { num: 23, cat: "ddos", tier: "Network", real: false, type: "STAGED_THEATER" },
    { num: 24, cat: "dns-spoofing", tier: "Network", real: false, type: "STAGED_THEATER" },
    { num: 25, cat: "mitm", tier: "Network", real: false, type: "STAGED_THEATER" },
    { num: 26, cat: "ransomware-behavioral", tier: "Network", real: false, type: "STAGED_THEATER" },
    { num: 27, cat: "trojan-behavioral", tier: "Network", real: false, type: "STAGED_THEATER" },
    { num: 28, cat: "spyware-behavioral", tier: "Network", real: false, type: "STAGED_THEATER" },
    { num: 29, cat: "botnet-c2", tier: "Network", real: false, type: "STAGED_THEATER" },
    { num: 30, cat: "compromised-iot", tier: "Network", real: false, type: "STAGED_THEATER" },

    // Batch 4: Attacks #31–37
    { num: 31, cat: "polymorphic-malware", tier: "Network", real: false, type: "STAGED_THEATER" },
    { num: 32, cat: "apt-stealth-intrusion", tier: "Network", real: false, type: "STAGED_COMPOSITE" },
    { num: 33, cat: "encrypted-c2", tier: "Network", real: false, type: "STAGED_THEATER" },
    { num: 34, cat: "ai-adaptive", tier: "Network", real: true, type: "REAL_SCRIPT" },
    { num: 35, cat: "supply-chain-compromise", tier: "Network", real: false, type: "STAGED_COMPOSITE" },
    { num: 36, cat: "double-extortion", tier: "Network", real: false, type: "STAGED_COMPOSITE" },
    { num: 37, cat: "zero-day-eval", tier: "Network", real: true, type: "REAL_SCRIPT" },
  ];

  let passed = 0;
  let failed = 0;

  for (const att of attacks) {
    const route = `/simulation/trigger/app/${att.cat}`;

    process.stdout.write(
      `[${att.num.toString().padStart(2, "0")}/37] ${att.cat.padEnd(28, " ")} [${att.tier.padEnd(8, " ")}] [${(att.real ? "REAL" : "STAGED").padEnd(6, " ")}] [${att.type.padEnd(16, " ")}] ... `
    );

    try {
      const res = await makeRequest(
        {
          host: "localhost",
          port: 3002,
          path: route,
          method: "POST",
          headers: { "Content-Type": "application/json" },
        },
        { category: att.cat }
      );

      if (res.status === 200 && res.data?.success) {
        console.log("✅ OK");
        passed++;
      } else {
        console.log(`❌ FAILED (${res.status}): ${JSON.stringify(res.data)}`);
        failed++;
      }
    } catch (err) {
      console.log(`❌ ERROR: ${err.message}`);
      failed++;
    }
  }

  console.log("================================================================================");
  console.log(`🏁 37-ATTACK SUITE RESULTS: ${passed}/37 PASSED | ${failed} FAILED`);
  console.log("================================================================================");
}

runAll37AttacksTest().catch(console.error);
