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

async function testPhase3Batch() {
  console.log("================================================================================");
  console.log("🔥 TESTING FINAL ATTACKS BATCH #31–37");
  console.log("================================================================================");

  const attacks = [
    { num: 31, cat: "polymorphic-malware", expectedField: "variants" },
    { num: 32, cat: "apt-stealth-intrusion", expectedField: "campaignId" },
    { num: 33, cat: "encrypted-c2", expectedField: "encryptedPayloadHex" },
    { num: 34, cat: "ai-adaptive", expectedField: "featureDeltas" },
    { num: 35, cat: "supply-chain-compromise", expectedField: "stages" },
    { num: 36, cat: "double-extortion", expectedField: "lockedFiles" },
    { num: 37, cat: "zero-day-eval", expectedField: "noveltyScore" },
  ];

  let passed = 0;
  for (const a of attacks) {
    const res = await makeRequest({
      host: "localhost",
      port: 3002,
      path: `/simulation/trigger/app/${a.cat}`,
      method: "POST",
      headers: { "Content-Type": "application/json" },
    }, { category: a.cat });

    console.log(`[${a.num}/37] Testing ${a.cat}... status=${res.status}, success=${res.data?.success}, keys=${Object.keys(res.data || {})}`);
    const staged = res.data?.stagedRecord || res.data?.data?.stagedRecord || res.data?.effectSummary?.stagedRecord || res.data;
    const hasField = staged && (staged[a.expectedField] !== undefined || res.data[a.expectedField] !== undefined || res.data.effectSummary?.[a.expectedField] !== undefined);

    if (res.status === 200 && res.data?.success && hasField) {
      console.log(`[${a.num}/37] ${a.cat.padEnd(26, " ")} ... ✅ PASSED (Verified field: ${a.expectedField}, ExploitBanner: "${(res.data.exploitBanner || '').slice(0, 45)}...")`);
      passed++;
    } else {
      console.log(`[${a.num}/37] ${a.cat.padEnd(26, " ")} ... ❌ FAILED (Status: ${res.status}, Body: ${JSON.stringify(res.data).slice(0, 150)}...)`);
    }
  }

  console.log("================================================================================");
  console.log(`🏁 BATCH #31–37 TEST RESULTS: ${passed}/${attacks.length} PASSED`);
  console.log("================================================================================");
}

testPhase3Batch().catch(console.error);
