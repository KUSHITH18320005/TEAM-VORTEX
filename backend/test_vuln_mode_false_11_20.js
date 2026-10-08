const {
  executeBruteforce,
  executeCredentialStuffing,
  executePasswordSpraying,
  executeAccountTakeover,
  executeIdor,
  executeAuthBypass,
  executeCsrf,
  executeSsrf,
  executeXxe,
  executePortScanning,
} = require("./playwrightRunner");

async function testSafeModeGating() {
  console.log("==================================================================");
  console.log("=== VERIFYING SAFE MODE GATING (VULN_MODE=false) FOR #11–#20 ===");
  console.log("==================================================================");

  const tests = [
    { name: "Attack #11 (bruteforce)", fn: () => executeBruteforce(false) },
    { name: "Attack #12 (credential-stuffing)", fn: () => executeCredentialStuffing(false) },
    { name: "Attack #13 (password-spraying)", fn: () => executePasswordSpraying(false) },
    { name: "Attack #14 (account-takeover)", fn: () => executeAccountTakeover(false) },
    { name: "Attack #15 (idor)", fn: () => executeIdor(false) },
    { name: "Attack #16 (auth-bypass)", fn: () => executeAuthBypass(false) },
    { name: "Attack #17 (csrf)", fn: () => executeCsrf(false) },
    { name: "Attack #18 (ssrf)", fn: () => executeSsrf(false) },
    { name: "Attack #19 (xxe)", fn: () => executeXxe(false) },
    { name: "Attack #20 (port-scanning-recon)", fn: () => executePortScanning(false) },
  ];

  let blockedCount = 0;
  for (const t of tests) {
    process.stdout.write(`Testing safe mode on ${t.name}... `);
    try {
      const res = await t.fn();
      if (res.status === "Blocked") {
        console.log(`🛡️ BLOCKED AS EXPECTED`);
        console.log(`   Exploit Banner: "${res.exploitBanner}"`);
        blockedCount++;
      } else {
        console.log(`❌ FAILED (Status returned: ${res.status})`);
      }
    } catch (e) {
      console.log(`❌ ERROR: ${e.message}`);
    }
  }

  console.log("==================================================================");
  console.log(`SAFE MODE GATING SUMMARY: ${blockedCount}/10 BLOCKED`);
  console.log("==================================================================");

  if (blockedCount < 10) {
    process.exit(1);
  }
}

testSafeModeGating();
