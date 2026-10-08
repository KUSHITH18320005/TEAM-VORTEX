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

async function runTests() {
  console.log("================================================================================");
  console.log("🚀 TESTING PHASE 3 ATTACK SIMULATION SUITE (#21–30)");
  console.log("================================================================================");

  const attacks = [
    { num: 21, cat: "network-service-enumeration", type: "REAL_TOOL", route: "/simulation/trigger/app/network-service-enumeration" },
    { num: 22, cat: "dos", type: "REAL_TOOL", route: "/simulation/trigger/app/dos" },
    { num: 23, cat: "ddos", type: "STAGED", route: "/simulation/trigger/theater/ddos" },
    { num: 24, cat: "dns-spoofing", type: "STAGED", route: "/simulation/trigger/theater/dns-spoofing" },
    { num: 25, cat: "mitm", type: "STAGED", route: "/simulation/trigger/theater/mitm" },
    { num: 26, cat: "ransomware-behavioral", type: "STAGED", route: "/simulation/trigger/theater/ransomware-behavioral" },
    { num: 27, cat: "trojan-behavioral", type: "STAGED", route: "/simulation/trigger/theater/trojan-behavioral" },
    { num: 28, cat: "spyware-behavioral", type: "STAGED", route: "/simulation/trigger/theater/spyware-behavioral" },
    { num: 29, cat: "botnet-c2", type: "STAGED", route: "/simulation/trigger/theater/botnet-c2" },
    { num: 30, cat: "compromised-iot", type: "STAGED", route: "/simulation/trigger/theater/compromised-iot" },
  ];

  let passed = 0;
  let failed = 0;

  for (const att of attacks) {
    console.log(`\n▶️ Testing Attack #${att.num} [${att.type}]: '${att.cat}' via ${att.route}...`);
    try {
      const res = await makeRequest({
        host: "localhost",
        port: 3002,
        path: att.route,
        method: "POST",
        headers: { "Content-Type": "application/json" },
      }, { category: att.cat });

      if (res.status === 200 && res.data && res.data.success) {
        console.log(`   ✅ Status 200 OK | Category: ${res.data.category}`);
        console.log(`   📄 Effect Title: ${res.data.effectSummary?.title}`);
        console.log(`   🛡️ Exploit Banner: ${res.data.effectSummary?.exploitBanner}`);

        if (att.cat === "network-service-enumeration") {
          const services = res.data.effectSummary?.discoveredServices;
          console.log(`   🔍 Discovered Services Count: ${services?.length || 0}`);
          if (!services || services.length === 0) {
            throw new Error("Discovered services table was empty");
          }
        } else if (att.cat === "dos") {
          const timeline = res.data.effectSummary?.latencyTimeline;
          console.log(`   ⚡ Load Timeline Samples: ${timeline?.length || 0} | Recovery: ${res.data.effectSummary?.recoveryTimeMs}ms`);
          if (!timeline || timeline.length === 0) {
            throw new Error("Latency timeline was empty");
          }
        } else {
          // Staged Impact Theater validation
          const rec = res.data.effectSummary?.stagedRecord;
          console.log(`   🎭 Replayed Dataset: ${rec?.dataset} | Target/Detail: ${JSON.stringify(rec?.details || rec?.ip)}`);
          if (!rec || !rec.dataset) {
            throw new Error("Staged dataset record missing dataset identifier");
          }
        }

        passed++;
      } else {
        console.log(`   ❌ Unexpected response: ${res.status}`, res.data);
        failed++;
      }
    } catch (err) {
      console.log(`   ❌ Error executing attack #${att.num} [${att.cat}]:`, err.message);
      failed++;
    }
  }

  // Also test dataset-record GET route
  console.log("\n▶️ Testing GET /simulation/dataset-record/:category endpoint directly...");
  try {
    const res = await makeRequest({
      host: "localhost",
      port: 3002,
      path: "/simulation/dataset-record/ddos",
      method: "GET",
    });
    if (res.status === 200 && res.data?.record?.dataset === "CICIDS2017") {
      console.log("   ✅ GET /simulation/dataset-record/ddos returned CICIDS2017 record");
    } else {
      console.log("   ❌ GET /simulation/dataset-record/ddos failed:", res.data);
      failed++;
    }
  } catch (err) {
    console.log("   ❌ Error on GET dataset-record:", err.message);
    failed++;
  }

  console.log("\n================================================================================");
  console.log(`🏁 PHASE 3 SUITE RESULTS: ${passed} PASSED | ${failed} FAILED`);
  console.log("================================================================================");

  if (failed > 0) process.exit(1);
}

runTests();
