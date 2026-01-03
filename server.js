const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const session = require("express-session");
const bcrypt = require("bcrypt");

const app = express();

/* ---------------- SESSION ---------------- */
app.use(
  session({
    secret: "inspection-secret-key",
    resave: false,
    saveUninitialized: false,
  })
);

/* ---------------- MIDDLEWARE ---------------- */
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use("/uploads", express.static("uploads"));
app.use("/reports", express.static("reports"));

/* ---------------- FOLDERS ---------------- */
for (const dir of ["uploads", "reports"]) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir);
}

/* ---------------- DATABASE ---------------- */
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
    rooms_count INTEGER,
    amenities TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS inspections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    property_id INTEGER,
    title TEXT,
    summary TEXT,
    inspector_name TEXT,
    tenant_name TEXT,
    inspection_date TEXT,
    status TEXT DEFAULT 'Draft'
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS photos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    inspection_id INTEGER,
    room TEXT,
    filename TEXT,
    comment TEXT
  )`);
});

/* ---------------- HELPERS ---------------- */
function esc(s) {
  return String(s || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect("/login");
  next();
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.session.user.role)) {
      return res.send("Access denied");
    }
    next();
  };
}

function pageStart(title, user) {
  return `
<link rel="stylesheet" href="/style.css">
<div class="container">
  <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:16px;">
    <div>
      <h1 style="margin:0;">${title}</h1>
      <div style="font-size:12px; color:#666;">
        Property Management System · Powered by CloudNet
      </div>
    </div>
    <div style="text-align:right; font-size:13px;">
      <div><b>${esc(user.email)}</b></div>
      <div style="color:#555;">Role: ${esc(user.role)}</div>
      <a href="/logout">Logout</a>
    </div>
  </div>
`;
}

function pageEnd() {
  return `</div>`;
}

/* ---------------- LOGIN ---------------- */
app.get("/login", (req, res) => {
  res.send(`
<link rel="stylesheet" href="/style.css">
<div class="container" style="max-width:420px; text-align:center;">
  <img src="/logo.png" style="max-width:120px; margin-bottom:16px;" />
  <h2>Property Management System</h2>
  <div style="font-size:13px; color:#666; margin-bottom:20px;">
    Powered by CloudNet
  </div>
  <form method="POST">
    <input name="email" placeholder="Email" required />
    <input type="password" name="password" placeholder="Password" required />
    <button style="width:100%; margin-top:10px;">Login</button>
  </form>
</div>
`);
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;

  db.get("SELECT * FROM users WHERE email=?", [email], (e, user) => {
    if (!user) return res.send("Invalid login");

    bcrypt.compare(password, user.password, (e2, ok) => {
      if (!ok) return res.send("Invalid login");

      req.session.user = {
        id: user.id,
        email: user.email,
        role: user.role,
      };
      res.redirect("/");
    });
  });
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/login"));
});

/* ---------------- HOME ---------------- */
app.get("/", requireLogin, (req, res) => {
  // TENANT = VIEW ONLY
  if (req.session.user.role === "tenant") {
    return res.send(
      pageStart("Tenant Dashboard", req.session.user) +
        "<p>You can only view inspection reports.</p>" +
        pageEnd()
    );
  }

  db.all("SELECT * FROM properties", (e, props) => {
    let html = pageStart("Dashboard", req.session.user);

    html += `
<h2>Add Property</h2>
<form method="POST" action="/add-property">
  <input name="address" placeholder="Complete Address" required />
  <input name="rooms_count" type="number" placeholder="Rooms Count" required />
  <textarea name="amenities" placeholder="Amenities"></textarea>
  <button>Add Property</button>
</form>
<hr/>
`;

    props.forEach(p => {
      html += `
<div class="card">
  <b>${esc(p.address)}</b><br/>
  Rooms: ${p.rooms_count}<br/>
  Amenities: ${esc(p.amenities || "-")}<br/>
  <a href="/property/${p.id}">Open</a>
</div>
`;
    });

    html += pageEnd();
    res.send(html);
  });
});

/* ---------------- ADMIN / INSPECTOR ONLY ---------------- */
app.post("/add-property", requireLogin, requireRole("admin", "inspector"), (req, res) => {
  const { address, rooms_count, amenities } = req.body;
  db.run(
    "INSERT INTO properties(address, rooms_count, amenities) VALUES(?,?,?)",
    [address, rooms_count, amenities || ""],
    () => res.redirect("/")
  );
});

/* ---------------- PROPERTY ---------------- */
app.get("/property/:id", requireLogin, (req, res) => {
  const pid = req.params.id;

  db.get("SELECT * FROM properties WHERE id=?", [pid], (e, prop) => {
    if (!prop) return res.send("Property not found");

    db.all("SELECT * FROM inspections WHERE property_id=?", [pid], (e2, ins) => {
      let html = pageStart("Property", req.session.user);

      html += `
<h2>${esc(prop.address)}</h2>
<p>Rooms: ${prop.rooms_count}<br/>Amenities: ${esc(prop.amenities)}</p>
<hr/>
`;

      ins.forEach(i => {
        html += `
<div class="card">
  <b>${esc(i.title)}</b> (${i.status})<br/>
  <a href="/inspection/${i.id}">Open</a>
</div>
`;
      });

      html += pageEnd();
      res.send(html);
    });
  });
});

/* ---------------- INSPECTION ---------------- */
const upload = multer({
  storage: multer.diskStorage({
    destination: "uploads",
    filename: (req, file, cb) =>
      cb(null, Date.now() + path.extname(file.originalname))
  })
});

app.get("/inspection/:id", requireLogin, (req, res) => {
  const iid = req.params.id;

  db.get(
    `SELECT i.*, p.address FROM inspections i
     JOIN properties p ON p.id=i.property_id WHERE i.id=?`,
    [iid],
    (e, insp) => {
      if (!insp) return res.send("Inspection not found");

      db.all("SELECT * FROM photos WHERE inspection_id=?", [iid], (e2, photos) => {
        let html = pageStart("Inspection", req.session.user);

        html += `
<h2>${esc(insp.address)}</h2>
<b>${esc(insp.title)}</b>
<p>${esc(insp.summary)}</p>
<hr/>
`;

        photos.forEach(p => {
          html += `
<img src="/uploads/${p.filename}" width="300"/><br/>
${esc(p.comment)}<br/><br/>
`;
        });

        html += pageEnd();
        res.send(html);
      });
    }
  );
});

/* ---------------- SERVER ---------------- */
app.listen(3000, () => {
  console.log("Running at http://localhost:3000");
});
