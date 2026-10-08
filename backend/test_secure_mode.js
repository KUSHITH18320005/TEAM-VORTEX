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

// We can test against current or simulated secure behavior
async function runSecureCheck() {
  console.log("=== Checking Secure Mitigation Logic ===");

  // NoSQL filter check logic
  const isSafe = (obj) => {
    if (typeof obj !== "object" || obj === null) return true;
    for (const key of Object.keys(obj)) {
      if (key.startsWith("$") || typeof obj[key] === "function") return false;
      if (typeof obj[key] === "object" && !isSafe(obj[key])) return false;
    }
    return true;
  };

  console.log("NoSQL {$gt: 0} blocked in safe mode:", !isSafe({ qty: { $gt: 0 } }));
  console.log("NoSQL {$where: ...} blocked in safe mode:", !isSafe({ $where: "1==1" }));
  console.log("Safe filter allowed in safe mode:", isSafe({ name: "INFY" }));

  // XSS sanitization check logic
  const sanitize = (str) =>
    String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");

  const xssPayload = "<script>alert(1)</script>";
  console.log("XSS sanitized:", sanitize(xssPayload));

  // Business logic check
  const validateOrder = (qty, price) => {
    const q = Number(qty);
    const p = Number(price);
    return !isNaN(q) && q > 0 && !isNaN(p) && p > 0;
  };
  console.log("Negative qty (-5) rejected in safe mode:", !validateOrder(-5, 100));
  console.log("Zero price (0) rejected in safe mode:", !validateOrder(10, 0));
  console.log("Valid order (10, 150.5) accepted in safe mode:", validateOrder(10, 150.5));
}

runSecureCheck();
