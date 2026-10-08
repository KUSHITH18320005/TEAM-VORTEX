const {
  executeXssStored,
  executeOpenRedirect,
  executeBusinessLogic,
  executeApiAbuse,
  executeNoRateLimit,
  executeDataExfil,
  executeJwtAbuse,
  executeSessionHijack,
  executeSessionFixation,
} = require("./playwrightRunner");

async function verifyVulnModeGating() {
  console.log("======================================================================");
  console.log("   VULN_MODE=false GATING VERIFICATION (ATTACKS #2–10)               ");
  console.log("======================================================================");

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

  // Attack 2: XSS Stored
  const resXss = await executeXssStored(false);
  assert(resXss.status === "Blocked", "Attack #2 (xss-stored) blocked in safe mode", JSON.stringify(resXss));

  // Attack 3: Open Redirect
  const resRedirect = await executeOpenRedirect(false);
  assert(resRedirect.status === "Blocked", "Attack #3 (open-redirect) blocked in safe mode", JSON.stringify(resRedirect));

  // Attack 4: Business Logic
  const resBiz = await executeBusinessLogic(false);
  assert(resBiz.status === "Blocked", "Attack #4 (business-logic) blocked in safe mode", JSON.stringify(resBiz));

  // Attack 5: API Abuse
  const resApi = await executeApiAbuse(false);
  assert(resApi.status === "Blocked", "Attack #5 (api-abuse) blocked in safe mode", JSON.stringify(resApi));

  // Attack 6: No Rate Limit
  const resRate = await executeNoRateLimit(false, 20);
  assert(resRate.status === "Blocked", "Attack #6 (no-rate-limit) blocked in safe mode", JSON.stringify(resRate));

  // Attack 7: Data Exfil
  const resExfil = await executeDataExfil(false);
  assert(resExfil.status === "Blocked", "Attack #7 (data-exfil) blocked in safe mode", JSON.stringify(resExfil));

  // Attack 8: JWT Abuse
  const resJwt = await executeJwtAbuse(false);
  assert(resJwt.status === "Blocked", "Attack #8 (jwt-abuse) blocked in safe mode", JSON.stringify(resJwt));

  // Attack 9: Session Hijack
  const resHijack = await executeSessionHijack(false);
  assert(resHijack.status === "Blocked", "Attack #9 (session-hijack) blocked in safe mode", JSON.stringify(resHijack));

  // Attack 10: Session Fixation
  const resFixation = await executeSessionFixation(false);
  assert(resFixation.status === "Blocked", "Attack #10 (session-fixation) blocked in safe mode", JSON.stringify(resFixation));

  console.log("\n======================================================================");
  console.log(`   GATING TEST SUMMARY: ${passed}/${total} Passed`);
  console.log("======================================================================");

  if (passed === total) {
    console.log("🎉 ALL 9 ATTACKS SUCCESSFULLY BLOCKED WHEN VULN_MODE=false!");
  } else {
    process.exitCode = 1;
  }
}

verifyVulnModeGating();
