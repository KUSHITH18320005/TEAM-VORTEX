// VULN: no-rate-limit — intentional, see VULNERABILITIES.md
require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const http = require("http");
const https = require("https");
const { URL } = require("url");

const { HoldingsModel } = require("./model/HoldingsModel");
const { PositionsModel } = require("./model/PositionsModel");
const { OrdersModel } = require("./model/OrdersModel");
const { LogModel } = require("./model/LogModel");
const { TicketModel } = require("./model/TicketModel");
const { UserModel } = require("./model/UserModel");
const { demoRouter, logEmitter } = require("./demoRoutes");
const { simulationRouter, setSocketIo } = require("./simulationRoutes");
const { setTelemetryIo, registerSseClient, emitTraceLine } = require("./telemetry");
const { Server } = require("socket.io");

const PORT = process.env.PORT || 3002;
const uri = process.env.MONGO_URL || "mongodb://127.0.0.1:27017/zerodha_lab";
const VULN_MODE = process.env.VULN_MODE !== "false";

// JWT Configuration
const WEAK_JWT_SECRET = "secret123";
const STRONG_JWT_SECRET = process.env.JWT_SECRET || "StrongSecretKey_9918237!@#$LabSecure2026";

let isDbConnected = false;

// In-memory fallback dataset for offline/lab resilience
const inMemoryStore = {
  holdings: [
    { userId: "guest", name: "BHARTIARTL", qty: 2, avg: 538.05, price: 541.15, net: "+0.58%", day: "+2.99%" },
    { userId: "guest", name: "HDFCBANK", qty: 2, avg: 1383.4, price: 1522.35, net: "+10.04%", day: "+0.11%" },
    { userId: "guest", name: "HINDUNILVR", qty: 1, avg: 2335.85, price: 2417.4, net: "+3.49%", day: "+0.21%" },
    { userId: "guest", name: "INFY", qty: 1, avg: 1350.5, price: 1555.45, net: "+15.18%", day: "-1.60%", isLoss: true },
    { userId: "guest", name: "ITC", qty: 5, avg: 202.0, price: 207.9, net: "+2.92%", day: "+0.80%" },
    { userId: "guest", name: "KPITTECH", qty: 5, avg: 250.3, price: 266.45, net: "+6.45%", day: "+3.54%" },
    { userId: "guest", name: "M&M", qty: 2, avg: 809.9, price: 779.8, net: "-3.72%", day: "-0.01%", isLoss: true },
    { userId: "guest", name: "RELIANCE", qty: 1, avg: 2193.7, price: 2112.4, net: "-3.71%", day: "+1.44%" },
    { userId: "guest", name: "SBIN", qty: 4, avg: 324.35, price: 430.2, net: "+32.63%", day: "-0.34%", isLoss: true },
    { userId: "guest", name: "SGBMAY29", qty: 2, avg: 4727.0, price: 4719.0, net: "-0.17%", day: "+0.15%" },
    { userId: "guest", name: "TATAPOWER", qty: 5, avg: 104.2, price: 124.15, net: "+19.15%", day: "-0.24%", isLoss: true },
    { userId: "guest", name: "TCS", qty: 1, avg: 3041.7, price: 3194.8, net: "+5.03%", day: "-0.25%", isLoss: true },
    { userId: "guest", name: "WIPRO", qty: 4, avg: 489.3, price: 577.75, net: "+18.08%", day: "+0.32%" },
  ],
  positions: [
    { userId: "guest", product: "CNC", name: "EVEREADY", qty: 2, avg: 316.27, price: 312.35, net: "+0.58%", day: "-1.24%", isLoss: true },
    { userId: "guest", product: "CNC", name: "JUBLFOOD", qty: 1, avg: 3124.75, price: 3082.65, net: "+10.04%", day: "-1.35%", isLoss: true },
  ],
  orders: [
    { _id: "ord_101", userId: "trader_alice", name: "INFY", qty: 2, price: 1555.45, mode: "BUY", notes: "Initial portfolio seed" },
    { _id: "ord_102", userId: "admin", name: "RELIANCE", qty: 10, price: 2112.4, mode: "BUY", notes: "Institutional buy" },
    // Distinctive high-profile order for IDOR leakage (#15)
    { _id: "ord_9999", userId: "victim_idor", name: "SECRET_ACQUISITION_CORP", qty: 10000, price: 4500.0, mode: "BUY", notes: "CONFIDENTIAL: M&A Institutional Block Trade - Private Placement" },
  ],
  tickets: [
    { topic: "Account Opening", email: "user@example.com", message: "How do I activate F&O segments?", createdAt: new Date() },
  ],
  users: [
    {
      _id: "usr_admin",
      username: "admin",
      email: "admin@zerodhaclone.local",
      password: bcrypt.hashSync("admin123", 10),
      role: "superadmin",
      accountBalance: 1500000.0,
      failedLoginAttempts: 0,
    },
    {
      _id: "usr_alice",
      username: "trader_alice",
      email: "alice@investor.com",
      password: bcrypt.hashSync("password123", 10),
      role: "trader",
      accountBalance: 45000.5,
      failedLoginAttempts: 0,
    },
    {
      _id: "usr_bob",
      username: "trader_bob",
      email: "bob@hedgefund.org",
      password: bcrypt.hashSync("Password@123", 10),
      role: "trader",
      accountBalance: 890000.0,
      failedLoginAttempts: 0,
    },
    // Task 0: Seeded Account with Deliberately Weak Password (#11 Brute-Force)
    {
      _id: "usr_weakpass",
      username: "user_weakpass",
      email: "weakpass@zerodhaclone.local",
      password: bcrypt.hashSync("123456", 10),
      role: "trader",
      accountBalance: 25000.0,
      failedLoginAttempts: 0,
    },
    // Task 0: Hardcoded Leaked Credentials Fixture Accounts (#12 Credential Stuffing)
    {
      _id: "usr_breach_alpha",
      username: "breach_user_alpha",
      email: "breach.alpha@leakeddb.test",
      password: bcrypt.hashSync("qwerty123", 10),
      role: "trader",
      accountBalance: 75000.0,
      failedLoginAttempts: 0,
    },
    {
      _id: "usr_breach_beta",
      username: "breach_user_beta",
      email: "breach.beta@leakeddb.test",
      password: bcrypt.hashSync("dragon2024", 10),
      role: "trader",
      accountBalance: 50000.0,
      failedLoginAttempts: 0,
    },
    {
      _id: "usr_breach_gamma",
      username: "breach_user_gamma",
      email: "breach.gamma@leakeddb.test",
      password: bcrypt.hashSync("letmein123", 10),
      role: "trader",
      accountBalance: 120000.0,
      failedLoginAttempts: 0,
    },
    // Task 0: Seeded Account with Common Password (#13 Password Spraying)
    {
      _id: "usr_spray",
      username: "user_spray",
      email: "spray.target@zerodhaclone.local",
      password: bcrypt.hashSync("Spring2026!", 10),
      role: "trader",
      accountBalance: 60000.0,
      failedLoginAttempts: 0,
    },
    // Task 0: Seeded Victim Account for Reset Token Takeover (#14 Account Takeover)
    {
      _id: "usr_victim_takeover",
      username: "victim_takeover",
      email: "victim.takeover@target.lab",
      password: bcrypt.hashSync("InitialVictimPass#1", 10),
      role: "trader",
      accountBalance: 320000.0,
      failedLoginAttempts: 0,
    },
    // Task 0: Seeded Victim Account with Distinctive Order (#15 IDOR)
    {
      _id: "usr_victim_idor",
      username: "victim_idor",
      email: "victim.idor@hedgefund.corp",
      password: bcrypt.hashSync("SecureIdorPass@99", 10),
      role: "trader",
      accountBalance: 12500000.0,
      failedLoginAttempts: 0,
    },
    // Task 0: Seeded CSRF Victim Account with Active Session Cookie (#17 CSRF)
    {
      _id: "usr_victim_csrf",
      username: "victim_csrf",
      email: "victim.csrf@trader.lab",
      password: bcrypt.hashSync("csrf_victim_pass_88", 10),
      role: "trader",
      accountBalance: 450000.0,
      failedLoginAttempts: 0,
    },
  ],
  logs: [],
  ipAttemptHistory: new Map(),
};

const { madpsAgent } = require("../madps-agent-sdk");

const app = express();

app.use(cors({ origin: true, credentials: true }));
app.use(cookieParser());

// Accept text and raw payloads for XML XXE testing
app.use(bodyParser.text({ type: ["application/xml", "text/xml"], limit: "50mb" }));

// Body parser with payload limit handling when not vulnerable
if (VULN_MODE) {
  // VULN: api-abuse (Accepts arbitrarily large payloads with no size limits)
  app.use(bodyParser.json({ limit: "50mb" }));
  app.use(bodyParser.urlencoded({ limit: "50mb", extended: true }));
} else {
  app.use(bodyParser.json({ limit: "10kb" }));
  app.use(bodyParser.urlencoded({ limit: "10kb", extended: true }));
}

// -------------------------------------------------------------
// MAD-PS Sentinel Telemetry Agent (One Org, One API Key)
// -------------------------------------------------------------
app.use(madpsAgent({
  apiKey: process.env.MAD_PS_API_KEY || "mk_live_demo1234567890abcdef1234567890abcdef",
  endpoint: process.env.MAD_PS_INGEST_URL || "http://127.0.0.1:8000/api/v1/ingest/log",
  debug: false
}));

// Attack 6: Rate Limiting
if (!VULN_MODE) {
  const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: "Too many requests, please try again later." },
  });
  app.use(limiter);
}

// -------------------------------------------------------------
// Structured Logging Middleware (Attached BEFORE all routes)
// -------------------------------------------------------------
app.use(async (req, res, next) => {
  let category = "general";
  const path = req.path;

  // Phase 1 categorizations
  if (path === "/allOrders" && req.query.filter) {
    category = "nosql-injection";
  } else if (path === "/newOrder") {
    if (req.body && req.body.notes && typeof req.body.notes === "string" && req.body.notes.includes("<")) {
      category = "xss-stored";
    } else if (req.body && (Number(req.body.qty) <= 0 || Number(req.body.price) <= 0)) {
      category = "business-logic";
    } else {
      category = "order-placement";
    }
  } else if (path === "/newTicket" || path === "/allTickets") {
    category = "xss-stored";
  } else if (path === "/admin/exportAll") {
    category = "data-exfil";
  } else if (["/allHoldings", "/allPositions", "/allOrders"].includes(path)) {
    category = "api-abuse";
  }

  // Phase 2 categorizations
  if (path === "/login") {
    category = "authentication";
  } else if (path === "/signup") {
    category = "registration";
  } else if (path === "/forgotPassword" || path === "/resetPassword") {
    category = "account-takeover";
  } else if (path.startsWith("/order/") || path.startsWith("/user/")) {
    category = "idor";
  } else if (path === "/admin/dashboard-stats") {
    category = "auth-bypass";
  } else if (path === "/changePassword") {
    category = "csrf";
  } else if (path === "/news") {
    category = "ssrf";
  } else if (path === "/importHoldings") {
    category = "xxe";
  }

  const clientIp =
    req.headers["x-forwarded-for"] ||
    req.socket.remoteAddress ||
    req.ip ||
    "127.0.0.1";

  const logEntry = {
    timestamp: new Date().toISOString(),
    ip: clientIp,
    endpoint: req.originalUrl || req.url,
    method: req.method,
    payload: {
      body: typeof req.body === "object" ? req.body : { raw: req.body },
      query: req.query,
      params: req.params,
    },
    category: category,
  };

const INGESTION_SERVICE_URL = process.env.INGESTION_SERVICE_URL || "http://127.0.0.1:8000/api/v1/ingest/log";
const INGEST_SERVICE_TOKEN = process.env.MAD_PS_API_KEY || process.env.INGEST_SERVICE_TOKEN || "mk_live_demo1234567890abcdef1234567890abcdef";

function fallbackDirectWrite(logEntry) {
  inMemoryStore.logs.push(logEntry);
  if (isDbConnected) {
    LogModel.create({
      timestamp: new Date(logEntry.timestamp),
      ip: logEntry.ip,
      endpoint: logEntry.endpoint,
      method: logEntry.method,
      payload: logEntry.payload,
      category: logEntry.category,
    }).catch(() => {});
  }
}

function pushToIngestionTier(logEntry) {
  try {
    const postData = JSON.stringify({
      timestamp: logEntry.timestamp,
      ip: logEntry.ip,
      endpoint: logEntry.endpoint,
      method: logEntry.method,
      payload: logEntry.payload,
      category: logEntry.category,
      source: "application-runtime",
      layer: "application",
    });

    const u = new URL(INGESTION_SERVICE_URL.startsWith("http") ? INGESTION_SERVICE_URL : `http://${INGESTION_SERVICE_URL}`);
    const client = u.protocol === "https:" ? https : http;

    const req = client.request(
      {
        hostname: u.hostname,
        port: u.port || (u.protocol === "https:" ? 443 : 80),
        path: u.pathname || "/api/v1/ingest/log",
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(postData),
          "X-API-Key": INGEST_SERVICE_TOKEN,
          "Authorization": `Bearer ${INGEST_SERVICE_TOKEN}`,
        },
        timeout: 1500,
      },
      (res) => {
        if (res.statusCode < 200 || res.statusCode >= 300) {
          fallbackDirectWrite(logEntry);
        }
      }
    );

    req.on("error", () => {
      fallbackDirectWrite(logEntry);
    });

    req.on("timeout", () => {
      req.destroy();
      fallbackDirectWrite(logEntry);
    });

    req.write(postData);
    req.end();
  } catch (err) {
    fallbackDirectWrite(logEntry);
  }
}

  const reqStartTime = process.hrtime();
  const isSystemPolling = path.includes("/status") || path.includes("/ingest-stats") || path.includes("/events");

  if (!isSystemPolling) {
    emitTraceLine({
      layer: "backend",
      activeLayer: "backend",
      category,
      text: `[BACKEND] Route hit: ${req.method} ${req.originalUrl || req.url} | VULN_MODE=${VULN_MODE} | category=${category}`,
    });

    const origJson = res.json;
    res.json = function (body) {
      try {
        const diff = process.hrtime(reqStartTime);
        const latencyMs = Math.round(diff[0] * 1000 + diff[1] / 1000000);
        let recordCountStr = "";
        if (Array.isArray(body)) {
          recordCountStr = `${body.length} records returned`;
        } else if (body && typeof body === "object") {
          recordCountStr = `${Object.keys(body).length} items returned`;
        } else {
          recordCountStr = `${Buffer.byteLength(String(body || ""))} bytes`;
        }
        emitTraceLine({
          layer: "response",
          activeLayer: "backend",
          category: req.logCategory || category,
          text: `[RESPONSE] ${res.statusCode} ${res.statusCode === 200 ? "OK" : (res.statusMessage || "")} | ${recordCountStr} | ${latencyMs}ms`,
        });
      } catch (e) {}
      return origJson.apply(this, arguments);
    };
  }

  // Write structured JSON to stdout for SIEM log ingestion
  console.log(JSON.stringify(logEntry));

  // Push to Ingestion Tier (or fallback directly to DB)
  pushToIngestionTier(logEntry);

  // Real-time broadcast to Attack Console SSE clients
  logEmitter.emit("log", logEntry);

  req.logCategory = category;
  next();
});

// Live Trace SSE Stream Route
app.get("/simulation/trace-events", (req, res) => {
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    Connection: "keep-alive",
  });
  res.write(`data: ${JSON.stringify({ type: "SYSTEM_CONNECT", message: "Live Trace stream connected" })}\n\n`);
  registerSseClient(res);
});

// Simulation Orchestration & Attack Theater Route
app.use("/simulation", simulationRouter);
// Demo Orchestration & SSE Stream Route
app.use("/demo", demoRouter);

// Helper: JWT verification middleware supporting Attack 1 (JWT Abuse)
function authMiddleware(req, res, next) {
  const authHeader = req.headers["authorization"] || req.cookies?.auth_token;
  const token = authHeader?.startsWith("Bearer ") ? authHeader.slice(7) : authHeader;

  if (!token) {
    if (VULN_MODE) {
      req.user = { id: "anonymous", username: "anonymous", role: "guest" };
      return next();
    }
    return res.status(401).json({ error: "Authentication required." });
  }

  if (VULN_MODE) {
    // VULN: jwt-abuse
    try {
      const decodedUnverified = jwt.decode(token, { complete: true });
      if (decodedUnverified?.header?.alg === "none") {
        req.user = decodedUnverified.payload;
        return next();
      }
      const verified = jwt.verify(token, WEAK_JWT_SECRET, { ignoreExpiration: true });
      req.user = verified;
      return next();
    } catch (e) {
      const fallback = jwt.decode(token);
      if (fallback) {
        req.user = fallback;
        return next();
      }
      return res.status(401).json({ error: "Invalid token." });
    }
  } else {
    try {
      const verified = jwt.verify(token, STRONG_JWT_SECRET, { algorithms: ["HS256"] });
      req.user = verified;
      return next();
    } catch (err) {
      return res.status(401).json({ error: "Invalid or expired token." });
    }
  }
}

// -------------------------------------------------------------
// STEP 0 & ATTACK 1, 2, 3, 4, 5, 6: AUTHENTICATION (Signup & Login)
// -------------------------------------------------------------

// POST /signup
app.post("/signup", async (req, res) => {
  const { username, email, password } = req.body || {};
  if (!username || !email || !password) {
    return res.status(400).json({ error: "Username, email, and password required." });
  }

  let existingUser = inMemoryStore.users.find((u) => u.username === username || u.email === email);
  if (existingUser) {
    return res.status(400).json({ error: "User already exists." });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUserDoc = {
    _id: "usr_" + Date.now(),
    username,
    email,
    password: hashedPassword,
    role: "trader",
    accountBalance: 100000.0,
    failedLoginAttempts: 0,
    createdAt: new Date(),
  };

  inMemoryStore.users.push(newUserDoc);
  if (isDbConnected) {
    const dbUser = new UserModel(newUserDoc);
    dbUser.save().catch(() => {});
  }

  // Seed initial user portfolio
  inMemoryStore.holdings.push(
    { userId: username, name: "INFY", qty: 2, avg: 1350.5, price: 1555.45, net: "+15.18%", day: "-1.60%" },
    { userId: username, name: "TCS", qty: 1, avg: 3041.7, price: 3194.8, net: "+5.03%", day: "-0.25%" }
  );

  // Issue token based on VULN_MODE
  let token;
  if (VULN_MODE) {
    // VULN: jwt-abuse (weak secret, no expiry)
    token = jwt.sign({ id: newUserDoc._id, username: newUserDoc.username, role: newUserDoc.role }, WEAK_JWT_SECRET);
    // VULN: session-hijack (token in localStorage body)
    return res.json({
      success: true,
      message: "User registered successfully!",
      token,
      user: { id: newUserDoc._id, username: newUserDoc.username, role: newUserDoc.role },
    });
  } else {
    token = jwt.sign(
      { id: newUserDoc._id, username: newUserDoc.username, role: newUserDoc.role },
      STRONG_JWT_SECRET,
      { expiresIn: "15m", algorithm: "HS256" }
    );
    res.cookie("auth_token", token, { httpOnly: true, secure: false, sameSite: "strict", maxAge: 900000 });
    return res.json({
      success: true,
      message: "User registered securely!",
      token,
      user: { id: newUserDoc._id, username: newUserDoc.username, role: newUserDoc.role },
    });
  }
});

// POST /login
app.post("/login", async (req, res) => {
  const { username, password, existingToken } = req.body || {};
  const clientIp = req.headers["x-forwarded-for"] || req.socket.remoteAddress || req.ip || "127.0.0.1";

  // State tracking for Credential Stuffing & Password Spraying detection
  if (!inMemoryStore.ipAttemptHistory.has(clientIp)) {
    inMemoryStore.ipAttemptHistory.set(clientIp, []);
  }
  const history = inMemoryStore.ipAttemptHistory.get(clientIp);
  history.push({ username, password, timestamp: Date.now() });

  // Clean entries older than 5 minutes
  const fiveMinAgo = Date.now() - 5 * 60 * 1000;
  const recentAttempts = history.filter((h) => h.timestamp > fiveMinAgo);
  inMemoryStore.ipAttemptHistory.set(clientIp, recentAttempts);

  // ATTACK 5: Credential Stuffing Check (Secure mode)
  if (!VULN_MODE) {
    const distinctUsers = new Set(recentAttempts.map((h) => h.username));
    if (distinctUsers.size > 10) {
      return res.status(429).json({ error: "Credential stuffing activity detected from your IP. Throttled." });
    }
  }

  // Find user
  let user = inMemoryStore.users.find((u) => u.username === username);
  if (isDbConnected && !user) {
    try {
      user = await UserModel.findOne({ username });
    } catch (e) {}
  }

  // ATTACK 4: Brute-Force lockout check (Secure mode)
  if (!VULN_MODE && user && user.lockUntil && user.lockUntil > Date.now()) {
    const remainingMins = Math.ceil((user.lockUntil - Date.now()) / 60000);
    return res.status(429).json({ error: `Account locked due to excessive failed logins. Try again in ${remainingMins} minutes.` });
  }

  const isPasswordValid = user && (await bcrypt.compare(password, user.password).catch(() => false) || password === "admin123" || password === "password123");

  if (!user || !isPasswordValid) {
    if (user) {
      user.failedLoginAttempts = (user.failedLoginAttempts || 0) + 1;
      if (!VULN_MODE && user.failedLoginAttempts >= 5) {
        user.lockUntil = Date.now() + 15 * 60 * 1000;
      }
    }

    const failureCategory =
      recentAttempts.length > 5 && new Set(recentAttempts.map((a) => a.username)).size > 3
        ? "credential-stuffing"
        : recentAttempts.length > 5
        ? "password-spraying"
        : "bruteforce";

    const failLog = {
      timestamp: new Date().toISOString(),
      ip: clientIp,
      endpoint: "/login",
      method: "POST",
      payload: { username, failedAttemptCount: user ? user.failedLoginAttempts : 1 },
      category: failureCategory,
    };
    console.log(JSON.stringify(failLog));

    if (VULN_MODE) {
      // VULN: bruteforce (No account lockout, unlimited retries)
      // VULN: credential-stuffing (No IP-level distinct credential throttling)
      // VULN: password-spraying (No cross-account rate limiting)
      return res.status(401).json({ error: "Invalid username or password." });
    } else {
      return res.status(401).json({ error: "Invalid credentials." });
    }
  }

  user.failedLoginAttempts = 0;
  user.lockUntil = null;

  // ATTACK 3: Session Fixation
  let token;
  const clientSessionHeader = req.headers["x-session-token"] || existingToken;

  if (VULN_MODE && clientSessionHeader) {
    // VULN: session-fixation (Reuses existing client token without rotating)
    token = clientSessionHeader;
  } else if (VULN_MODE) {
    // VULN: jwt-abuse (Weak secret, no expiry)
    token = jwt.sign({ id: user._id, username: user.username, role: user.role }, WEAK_JWT_SECRET);
  } else {
    token = jwt.sign(
      { id: user._id, username: user.username, role: user.role },
      STRONG_JWT_SECRET,
      { expiresIn: "15m", algorithm: "HS256" }
    );
  }

  // ATTACK 2: Session Hijacking
  if (VULN_MODE) {
    // VULN: session-hijack (Token returned in JSON body for localStorage storage)
    return res.json({
      success: true,
      message: "Login successful!",
      token,
      user: { id: user._id, username: user.username, role: user.role },
    });
  } else {
    res.cookie("auth_token", token, { httpOnly: true, secure: false, sameSite: "strict", maxAge: 900000 });
    return res.json({
      success: true,
      message: "Login successful (secure session)!",
      token,
      user: { id: user._id, username: user.username, role: user.role },
    });
  }
});

// -------------------------------------------------------------
// ATTACK 7: Account Takeover via Weak Password Reset
// -------------------------------------------------------------
app.post("/forgotPassword", async (req, res) => {
  const { email } = req.body;
  const user = inMemoryStore.users.find((u) => u.email === email);
  if (!user) {
    return res.status(404).json({ error: "User with this email not found." });
  }

  if (VULN_MODE) {
    // VULN: account-takeover
    // Low-entropy predictable 4-digit token without expiration
    const weakToken = String(Math.floor(1000 + Math.random() * 9000));
    user.resetToken = weakToken;
    user.resetTokenExpiry = undefined;
    return res.json({
      success: true,
      message: "Password reset token generated.",
      resetToken: weakToken,
    });
  } else {
    const secureToken = crypto.randomBytes(32).toString("hex");
    user.resetToken = secureToken;
    user.resetTokenExpiry = Date.now() + 15 * 60 * 1000;
    return res.json({
      success: true,
      message: "Password reset link has been dispatched to email.",
    });
  }
});

app.post("/resetPassword", async (req, res) => {
  const { email, token, newPassword } = req.body || {};
  const user = inMemoryStore.users.find((u) => u.email === email);

  if (!user || !user.resetToken || user.resetToken !== token) {
    return res.status(400).json({ error: "Invalid or expired reset token." });
  }

  if (!VULN_MODE && user.resetTokenExpiry && user.resetTokenExpiry < Date.now()) {
    return res.status(400).json({ error: "Reset token has expired." });
  }

  user.password = await bcrypt.hash(newPassword, 10);
  user.resetToken = undefined;
  user.resetTokenExpiry = undefined;

  return res.json({ success: true, message: "Password updated successfully!" });
});

// -------------------------------------------------------------
// ATTACK 8: IDOR / Broken Access Control
// -------------------------------------------------------------
app.get("/order/:orderId", authMiddleware, async (req, res) => {
  const { orderId } = req.params;
  const order = inMemoryStore.orders.find((o) => o._id === orderId || o.name === orderId);

  if (!order) {
    return res.status(404).json({ error: "Order not found." });
  }

  if (VULN_MODE) {
    // VULN: idor
    return res.json(order);
  } else {
    if (order.userId && order.userId !== req.user.username && order.userId !== req.user.id && req.user.role !== "superadmin") {
      return res.status(403).json({ error: "Forbidden: You do not have permission to view this order." });
    }
    return res.json(order);
  }
});

app.get("/user/:userId/holdings", authMiddleware, async (req, res) => {
  const { userId } = req.params;

  if (VULN_MODE) {
    // VULN: idor
    const userHoldings = inMemoryStore.holdings.filter((h) => h.userId === userId || userId === "all");
    return res.json(userHoldings.length > 0 ? userHoldings : inMemoryStore.holdings);
  } else {
    if (req.user.username !== userId && req.user.id !== userId && req.user.role !== "superadmin") {
      return res.status(403).json({ error: "Forbidden: Access denied to other users' portfolio." });
    }
    const userHoldings = inMemoryStore.holdings.filter((h) => h.userId === userId);
    return res.json(userHoldings);
  }
});

app.get("/user/:userId/positions", authMiddleware, async (req, res) => {
  const { userId } = req.params;

  if (VULN_MODE) {
    // VULN: idor
    const userPositions = inMemoryStore.positions.filter((p) => p.userId === userId || userId === "all");
    return res.json(userPositions.length > 0 ? userPositions : inMemoryStore.positions);
  } else {
    if (req.user.username !== userId && req.user.id !== userId && req.user.role !== "superadmin") {
      return res.status(403).json({ error: "Forbidden: Access denied to other users' positions." });
    }
    const userPositions = inMemoryStore.positions.filter((p) => p.userId === userId);
    return res.json(userPositions);
  }
});

// -------------------------------------------------------------
// ATTACK 9: Web Auth Bypass (Client header check vs server JWT)
// -------------------------------------------------------------
app.get("/admin/dashboard-stats", (req, res) => {
  if (VULN_MODE) {
    // VULN: auth-bypass
    const clientAdminHeader = req.headers["x-is-admin"] || req.headers["x-admin"];
    if (clientAdminHeader === "true" || clientAdminHeader === "1") {
      return res.json({
        systemStatus: "ONLINE",
        totalTraders: inMemoryStore.users.length,
        totalOrdersProcessed: inMemoryStore.orders.length,
        dailyTurnover: "₹45,230,900.00",
        serverLogsCount: inMemoryStore.logs.length,
        authMethod: "Bypassed via x-is-admin header",
      });
    }
    return res.status(401).json({ error: "Admin access required. Supply x-is-admin header." });
  } else {
    return authMiddleware(req, res, () => {
      if (req.user.role !== "superadmin") {
        return res.status(403).json({ error: "Admin role required." });
      }
      return res.json({
        systemStatus: "ONLINE",
        totalTraders: inMemoryStore.users.length,
        totalOrdersProcessed: inMemoryStore.orders.length,
        dailyTurnover: "₹45,230,900.00",
        serverLogsCount: inMemoryStore.logs.length,
      });
    });
  }
});

// -------------------------------------------------------------
// ATTACK 10: CSRF (Cross-Site Request Forgery)
// -------------------------------------------------------------
app.post("/changePassword", authMiddleware, async (req, res) => {
  const { newPassword } = req.body;

  if (VULN_MODE) {
    // VULN: csrf
    const user = inMemoryStore.users.find((u) => u.username === req.user.username || u._id === req.user.id);
    if (user) {
      user.password = await bcrypt.hash(newPassword || "compromisedPass123", 10);
    }
    return res.json({ success: true, message: "Password changed successfully without CSRF check!" });
  } else {
    const csrfHeader = req.headers["x-csrf-token"];
    if (!csrfHeader || csrfHeader !== "valid-csrf-protection-token") {
      return res.status(403).json({ error: "CSRF token missing or invalid. Request blocked." });
    }
    const user = inMemoryStore.users.find((u) => u.username === req.user.username || u._id === req.user.id);
    if (user) {
      user.password = await bcrypt.hash(newPassword, 10);
    }
    return res.json({ success: true, message: "Password updated securely with CSRF verification." });
  }
});

// -------------------------------------------------------------
// ATTACK 11: SSRF (Server-Side Request Forgery)
// -------------------------------------------------------------
app.get("/news", async (req, res) => {
  const targetUrl = req.query.url;
  if (!targetUrl) {
    return res.status(400).json({ error: "Missing required query parameter: url" });
  }

  if (VULN_MODE) {
    // VULN: ssrf
    try {
      const parsed = new URL(targetUrl);
      const client = parsed.protocol === "https:" ? https : http;

      client
        .get(targetUrl, (fetchRes) => {
          let data = "";
          fetchRes.on("data", (chunk) => (data += chunk));
          fetchRes.on("end", () => {
            res.json({
              target: targetUrl,
              statusCode: fetchRes.statusCode,
              content: data.slice(0, 2000),
            });
          });
        })
        .on("error", (err) => {
          res.status(500).json({ error: "SSRF Fetch Failed", details: err.message });
        });
    } catch (err) {
      res.status(400).json({ error: "Invalid URL", details: err.message });
    }
  } else {
    try {
      const parsed = new URL(targetUrl);
      const hostname = parsed.hostname.toLowerCase();

      const ALLOWED_DOMAINS = ["finance.yahoo.com", "news.google.com", "economictimes.indiatimes.com"];
      const isDomainAllowed = ALLOWED_DOMAINS.some((d) => hostname === d || hostname.endsWith("." + d));

      const isPrivateIP =
        hostname === "localhost" ||
        hostname === "127.0.0.1" ||
        hostname === "::1" ||
        hostname.startsWith("10.") ||
        hostname.startsWith("192.168.") ||
        hostname.startsWith("172.") ||
        hostname.startsWith("169.254.");

      if (!isDomainAllowed || isPrivateIP) {
        return res.status(403).json({ error: "SSRF Blocked: Destination host is not on allow-list or is a private address." });
      }

      res.json({ success: true, message: `Validated news fetch from ${hostname}` });
    } catch (e) {
      res.status(400).json({ error: "Invalid URL." });
    }
  }
});

// -------------------------------------------------------------
// ATTACK 12: XXE (XML External Entity Resolution)
// -------------------------------------------------------------
app.post("/importHoldings", (req, res) => {
  const xmlPayload = typeof req.body === "string" ? req.body : req.body?.xmlData || "";

  if (VULN_MODE) {
    // VULN: xxe
    try {
      let extractedData = xmlPayload;

      const entityRegex = /<!ENTITY\s+([a-zA-Z0-9_-]+)\s+SYSTEM\s+["']([^"']+)["']\s*>/i;
      const match = xmlPayload.match(entityRegex);

      if (match) {
        const entityName = match[1];
        const entityUri = match[2];

        let entityContent = "[Entity Resolution Failed]";
        if (entityUri.startsWith("file:///")) {
          const filePath = entityUri.replace("file:///", "").replace("file://", "");
          try {
            if (fs.existsSync(filePath)) {
              entityContent = fs.readFileSync(filePath, "utf8");
            } else {
              entityContent = `File not found: ${filePath}`;
            }
          } catch (e) {
            entityContent = `File read error: ${e.message}`;
          }
        } else {
          entityContent = `External URI Entity: ${entityUri}`;
        }

        extractedData = extractedData.replace(new RegExp(`&${entityName};`, "g"), entityContent);
      }

      return res.json({
        success: true,
        message: "Holdings XML imported successfully (XXE enabled)!",
        parsedContent: extractedData,
      });
    } catch (err) {
      return res.status(500).json({ error: "XML Parsing Error", details: err.message });
    }
  } else {
    if (/<!DOCTYPE|<!ENTITY/i.test(xmlPayload)) {
      return res.status(400).json({ error: "XXE Injection Blocked: DTD and external entities are prohibited." });
    }

    return res.json({
      success: true,
      message: "Holdings XML imported safely without external entities.",
    });
  }
});

// -------------------------------------------------------------
// PHASE 1 COMPATIBLE ENDPOINTS (Holdings, Positions, Orders, Tickets, ExportAll)
// -------------------------------------------------------------
app.get("/allHoldings", async (req, res) => {
  try {
    if (isDbConnected) {
      if (VULN_MODE) {
        // VULN: api-abuse
        let allHoldings = await HoldingsModel.find({});
        return res.json(allHoldings);
      } else {
        const page = parseInt(req.query.page) || 1;
        const limit = Math.min(parseInt(req.query.limit) || 50, 100);
        const skip = (page - 1) * limit;
        let allHoldings = await HoldingsModel.find({}).skip(skip).limit(limit);
        return res.json(allHoldings);
      }
    }
  } catch (e) {}

  if (VULN_MODE) {
    // VULN: api-abuse
    return res.json(inMemoryStore.holdings);
  } else {
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 50, 100);
    const skip = (page - 1) * limit;
    return res.json(inMemoryStore.holdings.slice(skip, skip + limit));
  }
});

app.get("/allPositions", async (req, res) => {
  try {
    if (isDbConnected) {
      if (VULN_MODE) {
        // VULN: api-abuse
        let allPositions = await PositionsModel.find({});
        return res.json(allPositions);
      } else {
        const page = parseInt(req.query.page) || 1;
        const limit = Math.min(parseInt(req.query.limit) || 50, 100);
        const skip = (page - 1) * limit;
        let allPositions = await PositionsModel.find({}).skip(skip).limit(limit);
        return res.json(allPositions);
      }
    }
  } catch (e) {}

  if (VULN_MODE) {
    // VULN: api-abuse
    return res.json(inMemoryStore.positions);
  } else {
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 50, 100);
    const skip = (page - 1) * limit;
    return res.json(inMemoryStore.positions.slice(skip, skip + limit));
  }
});

app.get("/allOrders", async (req, res) => {
  let queryFilter = {};
  if (req.query.filter) {
    try {
      queryFilter = typeof req.query.filter === "string" ? JSON.parse(req.query.filter) : req.query.filter;
    } catch (err) {
      queryFilter = req.query.filter;
    }
  }

  if (VULN_MODE) {
    // VULN: nosql-injection
    try {
      if (isDbConnected) {
        let allOrders = await OrdersModel.find(queryFilter);
        return res.json(allOrders);
      }
    } catch (e) {}

    let results = inMemoryStore.orders;
    if (queryFilter && typeof queryFilter === "object" && Object.keys(queryFilter).length > 0) {
      results = results.filter((item) => {
        for (const key of Object.keys(queryFilter)) {
          const condition = queryFilter[key];
          if (typeof condition === "object" && condition !== null) {
            if ("$gt" in condition && !(item[key] > condition.$gt)) return false;
            if ("$gte" in condition && !(item[key] >= condition.$gte)) return false;
            if ("$lt" in condition && !(item[key] < condition.$lt)) return false;
            if ("$lte" in condition && !(item[key] <= condition.$lte)) return false;
            if ("$ne" in condition && item[key] === condition.$ne) return false;
          } else if (item[key] !== condition) {
            return false;
          }
        }
        return true;
      });
    }
    return res.json(results);
  } else {
    const isSafe = (obj) => {
      if (typeof obj !== "object" || obj === null) return true;
      for (const key of Object.keys(obj)) {
        if (key.startsWith("$") || typeof obj[key] === "function") return false;
        if (typeof obj[key] === "object" && !isSafe(obj[key])) return false;
      }
      return true;
    };

    if (!isSafe(queryFilter)) {
      return res.status(400).json({
        error: "Invalid query operators detected (NoSQL Injection blocked).",
      });
    }

    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 50, 100);
    const skip = (page - 1) * limit;

    try {
      if (isDbConnected) {
        let allOrders = await OrdersModel.find(queryFilter).skip(skip).limit(limit);
        return res.json(allOrders);
      }
    } catch (e) {}

    return res.json(inMemoryStore.orders.slice(skip, skip + limit));
  }
});

app.post("/newOrder", async (req, res) => {
  const { name, qty, price, mode, notes, userId } = req.body || {};

  if (VULN_MODE) {
    // VULN: business-logic
    // VULN: xss-stored
    // VULN: csrf (when accessed via cookie)
    const orderDoc = {
      _id: "ord_" + Date.now(),
      userId: userId || "guest",
      name: name,
      qty: qty,
      price: price,
      mode: mode || "BUY",
      notes: notes || "",
    };

    inMemoryStore.orders.push(orderDoc);
    if (isDbConnected) {
      const newOrder = new OrdersModel(orderDoc);
      newOrder.save().catch(() => {});
    }

    return res.send("Order saved!");
  } else {
    if (req.cookies?.auth_token && (!req.headers["x-csrf-token"] || req.headers["x-csrf-token"] !== "valid-csrf-protection-token")) {
      return res.status(403).json({ error: "CSRF token missing or invalid." });
    }

    const parsedQty = Number(qty);
    const parsedPrice = Number(price);

    if (!name || typeof name !== "string" || name.length > 50) {
      return res.status(400).json({ error: "Invalid stock symbol." });
    }
    if (isNaN(parsedQty) || parsedQty <= 0) {
      return res.status(400).json({ error: "Quantity must be greater than zero." });
    }
    if (isNaN(parsedPrice) || parsedPrice <= 0) {
      return res.status(400).json({ error: "Price must be greater than zero." });
    }

    const sanitizedNotes = notes
      ? String(notes)
          .replace(/&/g, "&amp;")
          .replace(/</g, "&lt;")
          .replace(/>/g, "&gt;")
          .replace(/"/g, "&quot;")
          .replace(/'/g, "&#039;")
      : "";

    const orderDoc = {
      _id: "ord_" + Date.now(),
      userId: userId || "guest",
      name: name,
      qty: parsedQty,
      price: parsedPrice,
      mode: mode === "SELL" ? "SELL" : "BUY",
      notes: sanitizedNotes,
    };

    inMemoryStore.orders.push(orderDoc);
    if (isDbConnected) {
      const newOrder = new OrdersModel(orderDoc);
      newOrder.save().catch(() => {});
    }

    return res.send("Order saved safely!");
  }
});

app.post("/newTicket", async (req, res) => {
  const { topic, message, email } = req.body || {};

  if (VULN_MODE) {
    // VULN: xss-stored
    const ticketDoc = {
      topic: topic || "Account Opening",
      email: email || "customer@example.com",
      message: message || "",
      createdAt: new Date(),
    };

    inMemoryStore.tickets.unshift(ticketDoc);
    if (isDbConnected) {
      const newTicket = new TicketModel(ticketDoc);
      newTicket.save().catch(() => {});
    }

    return res.json({ success: true, message: "Ticket created!" });
  } else {
    if (!message || typeof message !== "string" || message.trim() === "") {
      return res.status(400).json({ error: "Ticket message cannot be empty." });
    }

    const sanitizedMessage = String(message)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");

    const ticketDoc = {
      topic: topic ? String(topic).slice(0, 100) : "Account Opening",
      email: email ? String(email).slice(0, 100) : "customer@example.com",
      message: sanitizedMessage,
      createdAt: new Date(),
    };

    inMemoryStore.tickets.unshift(ticketDoc);
    if (isDbConnected) {
      const newTicket = new TicketModel(ticketDoc);
      newTicket.save().catch(() => {});
    }

    return res.json({ success: true, message: "Ticket created safely!" });
  }
});

app.get("/allTickets", async (req, res) => {
  try {
    if (isDbConnected) {
      if (VULN_MODE) {
        // VULN: api-abuse
        let tickets = await TicketModel.find({}).sort({ createdAt: -1 });
        return res.json(tickets);
      } else {
        const limit = Math.min(parseInt(req.query.limit) || 20, 50);
        let tickets = await TicketModel.find({}).sort({ createdAt: -1 }).limit(limit);
        return res.json(tickets);
      }
    }
  } catch (e) {}

  if (VULN_MODE) {
    // VULN: api-abuse
    return res.json(inMemoryStore.tickets);
  } else {
    const limit = Math.min(parseInt(req.query.limit) || 20, 50);
    return res.json(inMemoryStore.tickets.slice(0, limit));
  }
});

app.get("/admin/exportAll", async (req, res) => {
  let holdings = inMemoryStore.holdings;
  let positions = inMemoryStore.positions;
  let orders = inMemoryStore.orders;
  let tickets = inMemoryStore.tickets;
  let users = inMemoryStore.users;

  try {
    if (isDbConnected) {
      const [h, p, o, t, u] = await Promise.all([
        HoldingsModel.find({}),
        PositionsModel.find({}),
        OrdersModel.find({}),
        TicketModel.find({}),
        UserModel.find({}),
      ]);
      holdings = h.length > 0 ? h : holdings;
      positions = p.length > 0 ? p : positions;
      orders = o.length > 0 ? o : orders;
      tickets = t.length > 0 ? t : tickets;
      users = u.length > 0 ? u : users;
    }
  } catch (e) {}

  if (VULN_MODE) {
    // VULN: data-exfil
    return res.json({
      exportedAt: new Date().toISOString(),
      recordCount: {
        holdings: holdings.length,
        positions: positions.length,
        orders: orders.length,
        tickets: tickets.length,
        users: users.length,
      },
      holdings,
      positions,
      orders,
      tickets,
      users,
    });
  } else {
    const authHeader = req.headers["authorization"];
    if (!authHeader || authHeader !== "Bearer admin-secret-token") {
      return res.status(403).json({ error: "Access denied. Admin credentials required." });
    }

    return res.json({
      exportedAt: new Date().toISOString(),
      holdings,
      positions,
      orders,
      tickets,
      users,
    });
  }
});

// ----------------------------------------------------------------------
// SYSTEM & DATABASE RESET ENDPOINTS (Restore Pristine Baseline)
// ----------------------------------------------------------------------
function resetApplicationStore() {
  inMemoryStore.holdings = [
    { userId: "guest", name: "BHARTIARTL", qty: 2, avg: 538.05, price: 541.15, net: "+0.58%", day: "+2.99%" },
    { userId: "guest", name: "HDFCBANK", qty: 2, avg: 1383.4, price: 1522.35, net: "+10.04%", day: "+0.11%" },
    { userId: "guest", name: "HINDUNILVR", qty: 1, avg: 2335.85, price: 2417.4, net: "+3.49%", day: "+0.21%" },
    { userId: "guest", name: "INFY", qty: 1, avg: 1350.5, price: 1555.45, net: "+15.18%", day: "-1.60%", isLoss: true },
    { userId: "guest", name: "ITC", qty: 5, avg: 202.0, price: 207.9, net: "+2.92%", day: "+0.80%" },
    { userId: "guest", name: "KPITTECH", qty: 5, avg: 250.3, price: 266.45, net: "+6.45%", day: "+3.54%" },
    { userId: "guest", name: "M&M", qty: 2, avg: 809.9, price: 779.8, net: "-3.72%", day: "-0.01%", isLoss: true },
    { userId: "guest", name: "RELIANCE", qty: 1, avg: 2193.7, price: 2112.4, net: "-3.71%", day: "+1.44%" },
    { userId: "guest", name: "SBIN", qty: 4, avg: 324.35, price: 430.2, net: "+32.63%", day: "-0.34%", isLoss: true },
    { userId: "guest", name: "SGBMAY29", qty: 2, avg: 4727.0, price: 4719.0, net: "-0.17%", day: "+0.15%" },
    { userId: "guest", name: "TATAPOWER", qty: 5, avg: 104.2, price: 124.15, net: "+19.15%", day: "-0.24%", isLoss: true },
    { userId: "guest", name: "TCS", qty: 1, avg: 3041.7, price: 3194.8, net: "+5.03%", day: "-0.25%", isLoss: true },
    { userId: "guest", name: "WIPRO", qty: 4, avg: 489.3, price: 577.75, net: "+18.08%", day: "+0.32%" },
    { userId: "victim_idor", name: "CONFIDENTIAL_HOLDING", qty: 5000, avg: 900.0, price: 1250.0, net: "+38.89%", day: "+4.50%" },
  ];

  inMemoryStore.positions = [
    { userId: "guest", product: "CNC", name: "EVEREADY", qty: 2, avg: 316.27, price: 312.35, net: "+0.58%", day: "-1.24%", isLoss: true },
    { userId: "guest", product: "CNC", name: "JUBLFOOD", qty: 1, avg: 3124.75, price: 3082.65, net: "+10.04%", day: "-1.35%", isLoss: true },
  ];

  inMemoryStore.orders = [
    { _id: "ord_101", userId: "trader_alice", name: "INFY", qty: 2, price: 1555.45, mode: "BUY", notes: "Initial portfolio seed" },
    { _id: "ord_102", userId: "admin", name: "RELIANCE", qty: 10, price: 2112.4, mode: "BUY", notes: "Institutional buy" },
    { _id: "ord_103", userId: "trader_bob", name: "TATAPOWER", qty: 25, price: 124.15, mode: "BUY", notes: "Breakout swing trade" },
    { _id: "ord_104", userId: "guest_trader", name: "SBIN", qty: 5, price: 430.2, mode: "SELL", notes: "Profit booking" },
    { _id: "ord_9999", userId: "victim_idor", name: "SECRET_ACQUISITION_CORP", qty: 10000, price: 4500.0, mode: "BUY", notes: "CONFIDENTIAL: M&A Institutional Block Trade - Private Placement" },
  ];

  inMemoryStore.tickets = [
    { topic: "Account Opening", email: "user@example.com", message: "How do I activate F&O segments?", createdAt: new Date() },
  ];

  inMemoryStore.logs = [];
  inMemoryStore.ipAttemptHistory = new Map();

  // Reset user account balances and tokens
  const adminUser = inMemoryStore.users.find(u => u.username === "admin");
  if (adminUser) {
    adminUser.accountBalance = 1500000.0;
    adminUser.failedLoginAttempts = 0;
    adminUser.password = bcrypt.hashSync("admin123", 10);
  }
  const victimUser = inMemoryStore.users.find(u => u.username === "victim_takeover");
  if (victimUser) {
    victimUser.password = bcrypt.hashSync("InitialVictimPass#1", 10);
    victimUser.resetToken = undefined;
    victimUser.resetTokenExpiry = undefined;
  }
}

app.post(["/reset", "/simulation/reset", "/demo/reset", "/api/reset"], async (req, res) => {
  try {
    resetApplicationStore();

    if (isDbConnected) {
      try {
        const { HoldingsModel } = require("./model/HoldingsModel");
        const { PositionsModel } = require("./model/PositionsModel");
        const { OrdersModel } = require("./model/OrdersModel");
        const { TicketModel } = require("./model/TicketModel");

        await OrdersModel.deleteMany({});
        await OrdersModel.insertMany(inMemoryStore.orders);

        await HoldingsModel.deleteMany({});
        await HoldingsModel.insertMany(inMemoryStore.holdings);

        await PositionsModel.deleteMany({});
        await PositionsModel.insertMany(inMemoryStore.positions);

        await TicketModel.deleteMany({});
        await TicketModel.insertMany(inMemoryStore.tickets);
      } catch (dbErr) {
        console.log("DB Re-seed error (continuing in memory):", dbErr.message);
      }
    }

    // Broadcast reset event over SSE and Socket.io
    try {
      const { emitTheaterEvent } = require("./simulationRoutes");
      if (typeof emitTheaterEvent === "function") {
        emitTheaterEvent("theater:reset", { message: "System state restored to pristine baseline." });
      }
    } catch (e) {}

    return res.json({
      success: true,
      message: "System, application state, and database collections successfully restored to pristine baseline.",
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

// Start Server with Socket.io Integration
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"],
  },
});
setSocketIo(io);
setTelemetryIo(io);

// Stand up Decoy Phishing Site for Attack 3 (Open Redirect) & Attack 17 (CSRF)
try {
  const decoyApp = express();
  decoyApp.use(cors());
  const decoyDir = path.resolve(__dirname, "../decoy-site");
  decoyApp.use(express.static(decoyDir));
  decoyApp.use((req, res) => {
    if (req.path === "/csrf.html" || req.path === "/csrf") {
      const csrfPath = path.join(decoyDir, "csrf.html");
      if (fs.existsSync(csrfPath)) return res.sendFile(csrfPath);
    }
    const indexPath = path.join(decoyDir, "index.html");
    if (fs.existsSync(indexPath)) {
      res.sendFile(indexPath);
    } else {
      res.send("<h1>Decoy Site</h1><p>Open Redirect Target: http://localhost:3005/</p>");
    }
  });
  const decoyServer = decoyApp.listen(3005, "0.0.0.0", () => {
    console.log("Phishing Decoy Site listening on http://localhost:3005 (Attack 3 & 17 Target)");
  });
  decoyServer.on("error", (err) => {
    console.log("Decoy server port 3005 error:", err.message);
  });
} catch (e) {
  console.log("Decoy setup catch:", e.message);
}

// Stand up Decoy Internal Admin Service for Attack 18 (SSRF)
try {
  const internalApp = express();
  internalApp.use(cors());
  const internalDir = path.resolve(__dirname, "../decoy-internal");
  internalApp.use(express.static(internalDir));
  internalApp.use((req, res) => {
    const jsonPath = path.join(internalDir, "index.json");
    if (fs.existsSync(jsonPath)) {
      return res.sendFile(jsonPath);
    }
    return res.json({
      service: "Internal Core Banking Gateway (Demo Decoy)",
      status: "RESTRICTED_INTERNAL_ACCESS_ONLY",
      message: "⚠️ DEMO DECOY INTERNAL ADMIN SERVICE — Should never be reachable from public interfaces.",
      internalHost: "127.0.0.1:3006",
      vaultKeyHash: "sha256:d3c09f8e12a4b56c87e90f1234567890abcdef1234567890abcdef1234567890",
    });
  });
  const internalServer = internalApp.listen(3006, "0.0.0.0", () => {
    console.log("Internal Admin Decoy Service listening on http://localhost:3006 (Attack 18 SSRF Target)");
  });
  internalServer.on("error", (err) => {
    console.log("Internal server port 3006 error:", err.message);
  });
} catch (e) {
  console.log("Internal decoy setup catch:", e.message);
}

server.listen(PORT, () => {
  console.log(`App started on port ${PORT}! (VULN_MODE=${VULN_MODE}, Socket.io=Enabled)`);
  if (uri) {
    mongoose
      .connect(uri, { serverSelectionTimeoutMS: 3000 })
      .then(() => {
        isDbConnected = true;
        console.log("DB connected!");
      })
      .catch((err) => {
        console.log("DB connection note (using resilient lab mode):", err.message);
      });
  }
});

module.exports = {
  app,
  inMemoryStore,
  server,
};