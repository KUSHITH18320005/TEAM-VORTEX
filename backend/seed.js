require("dotenv").config();
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const { HoldingsModel } = require("./model/HoldingsModel");
const { PositionsModel } = require("./model/PositionsModel");
const { OrdersModel } = require("./model/OrdersModel");
const { TicketModel } = require("./model/TicketModel");
const { UserModel } = require("./model/UserModel");
const { LogModel } = require("./model/LogModel");

const uri = process.env.MONGO_URL || "mongodb://127.0.0.1:27017/zerodha_lab";

const demoUsers = [
  {
    username: "admin",
    email: "admin@zerodhaclone.local",
    password: bcrypt.hashSync("admin123", 10),
    role: "superadmin",
    accountBalance: 1500000.0,
    failedLoginAttempts: 0,
  },
  {
    username: "trader_alice",
    email: "alice@investor.com",
    password: bcrypt.hashSync("password123", 10),
    role: "trader",
    accountBalance: 45000.5,
    failedLoginAttempts: 0,
  },
  {
    username: "trader_bob",
    email: "bob@hedgefund.org",
    password: bcrypt.hashSync("Password@123", 10),
    role: "trader",
    accountBalance: 890000.0,
    failedLoginAttempts: 0,
  },
  {
    username: "guest_trader",
    email: "guest@zerodhaclone.local",
    password: bcrypt.hashSync("guest123", 10),
    role: "trader",
    accountBalance: 10000.0,
    failedLoginAttempts: 0,
  },
  // Task 0: Seeded Account with Deliberately Weak Password (#11 Brute-Force)
  {
    username: "user_weakpass",
    email: "weakpass@zerodhaclone.local",
    password: bcrypt.hashSync("123456", 10),
    role: "trader",
    accountBalance: 25000.0,
    failedLoginAttempts: 0,
  },
  // Task 0: Hardcoded Leaked Credentials Fixture Accounts (#12 Credential Stuffing)
  {
    username: "breach_user_alpha",
    email: "breach.alpha@leakeddb.test",
    password: bcrypt.hashSync("qwerty123", 10),
    role: "trader",
    accountBalance: 75000.0,
    failedLoginAttempts: 0,
  },
  {
    username: "breach_user_beta",
    email: "breach.beta@leakeddb.test",
    password: bcrypt.hashSync("dragon2024", 10),
    role: "trader",
    accountBalance: 50000.0,
    failedLoginAttempts: 0,
  },
  {
    username: "breach_user_gamma",
    email: "breach.gamma@leakeddb.test",
    password: bcrypt.hashSync("letmein123", 10),
    role: "trader",
    accountBalance: 120000.0,
    failedLoginAttempts: 0,
  },
  // Task 0: Seeded Account with Common Password (#13 Password Spraying)
  {
    username: "user_spray",
    email: "spray.target@zerodhaclone.local",
    password: bcrypt.hashSync("Spring2026!", 10),
    role: "trader",
    accountBalance: 60000.0,
    failedLoginAttempts: 0,
  },
  // Task 0: Seeded Victim Account for Reset Token Takeover (#14 Account Takeover)
  {
    username: "victim_takeover",
    email: "victim.takeover@target.lab",
    password: bcrypt.hashSync("InitialVictimPass#1", 10),
    role: "trader",
    accountBalance: 320000.0,
    failedLoginAttempts: 0,
  },
  // Task 0: Seeded Victim Account with Distinctive Order (#15 IDOR)
  {
    username: "victim_idor",
    email: "victim.idor@hedgefund.corp",
    password: bcrypt.hashSync("SecureIdorPass@99", 10),
    role: "trader",
    accountBalance: 12500000.0,
    failedLoginAttempts: 0,
  },
  // Task 0: Seeded CSRF Victim Account with Active Session Cookie (#17 CSRF)
  {
    username: "victim_csrf",
    email: "victim.csrf@trader.lab",
    password: bcrypt.hashSync("csrf_victim_pass_88", 10),
    role: "trader",
    accountBalance: 450000.0,
    failedLoginAttempts: 0,
  },
];

const demoHoldings = [
  { userId: "trader_alice", name: "BHARTIARTL", qty: 4, avg: 538.05, price: 541.15, net: "+0.58%", day: "+2.99%" },
  { userId: "trader_alice", name: "HDFCBANK", qty: 2, avg: 1383.4, price: 1522.35, net: "+10.04%", day: "+0.11%" },
  { userId: "trader_alice", name: "HINDUNILVR", qty: 1, avg: 2335.85, price: 2417.4, net: "+3.49%", day: "+0.21%" },
  { userId: "trader_alice", name: "INFY", qty: 5, avg: 1350.5, price: 1555.45, net: "+15.18%", day: "-1.60%", isLoss: true },
  { userId: "trader_bob", name: "ITC", qty: 15, avg: 202.0, price: 207.9, net: "+2.92%", day: "+0.80%" },
  { userId: "trader_bob", name: "KPITTECH", qty: 8, avg: 250.3, price: 266.45, net: "+6.45%", day: "+3.54%" },
  { userId: "trader_bob", name: "M&M", qty: 6, avg: 809.9, price: 779.8, net: "-3.72%", day: "-0.01%", isLoss: true },
  { userId: "trader_bob", name: "RELIANCE", qty: 10, avg: 2193.7, price: 2112.4, net: "-3.71%", day: "+1.44%" },
  { userId: "admin", name: "SBIN", qty: 25, avg: 324.35, price: 430.2, net: "+32.63%", day: "-0.34%", isLoss: true },
  { userId: "admin", name: "SGBMAY29", qty: 10, avg: 4727.0, price: 4719.0, net: "-0.17%", day: "+0.15%" },
  { userId: "admin", name: "TATAPOWER", qty: 50, avg: 104.2, price: 124.15, net: "+19.15%", day: "-0.24%", isLoss: true },
  { userId: "guest", name: "TCS", qty: 3, avg: 3041.7, price: 3194.8, net: "+5.03%", day: "-0.25%", isLoss: true },
  { userId: "guest", name: "WIPRO", qty: 12, avg: 489.3, price: 577.75, net: "+18.08%", day: "+0.32%" },
  { userId: "victim_idor", name: "CONFIDENTIAL_HOLDING", qty: 5000, avg: 900.0, price: 1250.0, net: "+38.89%", day: "+4.50%" },
];

const demoPositions = [
  { userId: "trader_alice", product: "CNC", name: "EVEREADY", qty: 2, avg: 316.27, price: 312.35, net: "+0.58%", day: "-1.24%", isLoss: true },
  { userId: "trader_bob", product: "CNC", name: "JUBLFOOD", qty: 1, avg: 3124.75, price: 3082.65, net: "+10.04%", day: "-1.35%", isLoss: true },
  { userId: "admin", product: "MIS", name: "TATASTEEL", qty: 100, avg: 142.5, price: 148.2, net: "+4.00%", day: "+1.80%", isLoss: false },
];

const demoOrders = [
  { _id: "ord_101", userId: "trader_alice", name: "INFY", qty: 2, price: 1555.45, mode: "BUY", notes: "Initial portfolio seed" },
  { _id: "ord_102", userId: "admin", name: "RELIANCE", qty: 10, price: 2112.4, mode: "BUY", notes: "Institutional treasury purchase" },
  { _id: "ord_103", userId: "trader_bob", name: "TATAPOWER", qty: 25, price: 124.15, mode: "BUY", notes: "Breakout swing trade" },
  { _id: "ord_104", userId: "guest_trader", name: "SBIN", qty: 5, price: 430.2, mode: "SELL", notes: "Profit booking" },
  // Distinctive high-profile order for IDOR leakage (#15)
  { _id: "ord_9999", userId: "victim_idor", name: "SECRET_ACQUISITION_CORP", qty: 10000, price: 4500.0, mode: "BUY", notes: "CONFIDENTIAL: M&A Institutional Block Trade - Private Placement" },
];

const demoTickets = [
  { topic: "Account Opening", email: "alice@investor.com", message: "How do I activate F&O segments on my trading account?", createdAt: new Date(Date.now() - 3600000) },
  { topic: "Trading & Markets", email: "bob@hedgefund.org", message: "Need clarification regarding intraday margin multipliers for index options.", createdAt: new Date(Date.now() - 7200000) },
  { topic: "Security & Profile", email: "admin@zerodhaclone.local", message: "Security audit note: Ensure multi-factor authentication policies are enforced in production.", createdAt: new Date() },
];

async function seedDatabase() {
  console.log("=== Starting Database Seeding for Zerodha Lab ===");
  console.log("Connecting to:", uri.replace(/:([^@]+)@/, ":****@"));

  try {
    await mongoose.connect(uri, { serverSelectionTimeoutMS: 5000 });
    console.log("Connected to MongoDB successfully.");

    // Clear existing collections
    console.log("Clearing existing collections...");
    await Promise.all([
      UserModel.deleteMany({}),
      HoldingsModel.deleteMany({}),
      PositionsModel.deleteMany({}),
      OrdersModel.deleteMany({}),
      TicketModel.deleteMany({}),
    ]);

    // Insert demo seed data
    console.log("Inserting demo records...");
    await Promise.all([
      UserModel.insertMany(demoUsers),
      HoldingsModel.insertMany(demoHoldings),
      PositionsModel.insertMany(demoPositions),
      OrdersModel.insertMany(demoOrders),
      TicketModel.insertMany(demoTickets),
    ]);

    console.log("Seed Completed Successfully!");
    console.log(`- Users: ${demoUsers.length}`);
    console.log(`- Holdings: ${demoHoldings.length}`);
    console.log(`- Positions: ${demoPositions.length}`);
    console.log(`- Orders: ${demoOrders.length}`);
    console.log(`- Tickets: ${demoTickets.length}`);

    await mongoose.disconnect();
    console.log("Database connection closed.");
    process.exit(0);
  } catch (err) {
    console.log("Database connection failed or timed out:", err.message);
    console.log("Note: The server includes built-in in-memory fallbacks with this exact seed data so all attacks remain functional even in offline/lab environments.");
    process.exit(0);
  }
}

seedDatabase();
