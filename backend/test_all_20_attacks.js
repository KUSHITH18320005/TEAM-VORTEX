const http = require("http");

const ALL_20_ATTACKS = [
  // Phase 1: Attacks 1-10
  "nosql-injection",
  "xss-stored",
  "open-redirect",
  "business-logic",
  "api-abuse",
  "no-rate-limit",
  "data-exfil",
  "jwt-abuse",
  "session-hijack",
  "session-fixation",
  // Phase 2: Attacks 11-20
  "bruteforce",
  "credential-stuffing",
  "password-spraying",
  "account-takeover",
  "idor",
  "auth-bypass",
  "csrf",
  "ssrf",
  "xxe",
  "port-scanning-recon",
];

function triggerAttack(category) {
  return new Promise((resolve, reject) => {
    const postData = JSON.stringify({ category });
    const req = http.request(
      {
        host: "localhost",
        port: 3002,
        path: `/simulation/trigger/app/${category}`,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(postData),
        },
      },
      (res) => {
        let body = "";
        res.on("data", (chunk) => (body += chunk));
        res.on("end", () => {
          try {
            resolve({ statusCode: res.statusCode, body: JSON.parse(body) });
          } catch (e) {
            resolve({ statusCode: res.statusCode, body: { raw: body } });
          }
        });
      }
    );

    req.on("error", reject);
    req.write(postData);
    req.end();
  });
}

async function runAll20() {
  console.log("==================================================================");
  console.log("=== STARTING FULL END-TO-END VERIFICATION: ALL 20 ATTACKS ===");
  console.log("==================================================================");
  let passed = 0;
  let failed = 0;

  for (let i = 0; i < ALL_20_ATTACKS.length; i++) {
    const cat = ALL_20_ATTACKS[i];
    const num = i + 1;
    process.stdout.write(`[${num}/20] Testing Attack #${num} (${cat})... `);

    try {
      const res = await triggerAttack(cat);
      if (res.statusCode === 200 && res.body.success) {
        console.log(`✅ PASSED`);
        passed++;
      } else {
        console.log(`❌ FAILED (Status: ${res.statusCode})`, res.body);
        failed++;
      }
    } catch (err) {
      console.log(`❌ ERROR: ${err.message}`);
      failed++;
    }
  }

  console.log("==================================================================");
  console.log(`FULL TEST SUMMARY: ${passed}/20 PASSED (${failed} FAILED)`);
  console.log("==================================================================");

  if (failed > 0) {
    process.exit(1);
  }
}

runAll20();
