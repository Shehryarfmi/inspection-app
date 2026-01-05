const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const session = require("express-session");
const bcrypt = require("bcrypt");

const app = express();

/* ---------- SESSION ---------- */
app.use(
  session({
    secret: "inspection-secret-key",
    resave: false,
    saveUninitialized: false,
  })
);

/* ---------- MIDDLEWARE ---------- */
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use("/uploads", express.static("uploads"));

/* ---------- FOLDERS ---------- */
["uploads"].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir);
});

/* ---------- DATABASE ---------- */
const db = new sqlite3.Database(path.join(__dirname, "app.db"));

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password TEXT,
    role TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS properties (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    address TEXT,
    landlord_email TEXT,
    tenant_email TEXT
  )`);
});

/* ---------- SAFE DEMO USERS ---------- */
const users = [
  ["admin@demo.com", "admin123", "admin"],
  ["landlord@demo.com", "landlord123", "landlord"],
  ["tenant@demo.com", "tenant123", "tenant"],
  ["inspector@demo.com", "inspector123", "inspector"]
];

users.forEach(u => {
  bcrypt.hash(u[1], 10, (e, hash) => {
    db.run(
      "INSERT OR IGNORE INTO users(email,password,role) VALUES(?,?,?)",
      [u[0], hash, u[2]]
    );
  });
});

/* ---------- HELPERS ---------- */
function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect("/login");
  next();
}

function esc(s) {
  return String(s || "").replace(/[&<>"']/g, m =>
    ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;" }[m])
  );
}

/* ---------- LOGIN ---------- */
app.get("/login", (req, res) => {
  res.send(`
  <h2>Property Management System</h2>
  <form method="POST">
    <input name="email" placeholder="Email" required />
    <input type="password" name="password" placeholder="Password" required />
    <button>Login</button>
  </form>
  `);
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;
  db.get("SELECT * FROM users WHERE email=?", [email], (e, user) => {
    if (!user) return res.send("Invalid login");
    bcrypt.compare(password, user.password, (e2, ok) => {
      if (!ok) return res.send("Invalid login");
      req.session.user = user;
      res.redirect("/");
    });
  });
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/login"));
});

/* ---------- DASHBOARD ---------- */
app.get("/", requireLogin, (req, res) => {
  db.all("SELECT * FROM properties", (e, rows) => {
    let html = `<h2>Welcome ${esc(req.session.user.role)}</h2>
    <a href="/logout">Logout</a><hr/>`;

    if (req.session.user.role !== "tenant") {
      html += `
      <form method="POST" action="/add-property">
        <input name="address" placeholder="Property Address" required />
        <input name="landlord_email" placeholder="Landlord Email" required />
        <input name="tenant_email" placeholder="Tenant Email" />
        <button>Add Property</button>
      </form><hr/>`;
    }

    rows.forEach(p => {
      if (
        req.session.user.role === "admin" ||
        p.landlord_email === req.session.user.email ||
        p.tenant_email === req.session.user.email
      ) {
        html += `<div><b>${esc(p.address)}</b></div>`;
      }
    });

    res.send(html);
  });
});

app.post("/add-property", requireLogin, (req, res) => {
  db.run(
    "INSERT INTO properties(address,landlord_email,tenant_email) VALUES(?,?,?)",
    [req.body.address, req.body.landlord_email, req.body.tenant_email],
    () => res.redirect("/")
  );
});

/* ---------- SERVER ---------- */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("Server running on port", PORT);
});
