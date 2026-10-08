const http = require("http");

const ATTACKS_11_20 = [
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

async function runAll10() {
  console.log("=== STARTING AUTOMATED TEST SUITE: ATTACKS #11 TO #20 ===");
  let passed = 0;
  let failed = 0;

  for (let i = 0; i < ATTACKS_11_20.length; i++) {
    const cat = ATTACKS_11_20[i];
    const num = i + 11;
    process.stdout.write(`Testing Attack #${num} (${cat})... `);

    try {
      const res = await triggerAttack(cat);
      if (res.statusCode === 200 && res.body.success) {
        console.log(`✅ PASSED (${res.body.action || "Executed"})`);
        if (res.body.effectSummary?.exploitBanner) {
          console.log(`   Banner: "${res.body.effectSummary.exploitBanner}"`);
        }
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

  console.log("=========================================================");
  console.log(`SUMMARY: ${passed}/${ATTACKS_11_20.length} passed, ${failed} failed.`);
  console.log("=========================================================");

  if (failed > 0) {
    process.exit(1);
  }
}

runAll10();
