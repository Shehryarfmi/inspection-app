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

/* ---------------- FOLDERS ---------------- */
["uploads"].forEach((d) => {
  if (!fs.existsSync(d)) fs.mkdirSync(d);
});

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
    landlord_email TEXT,
    tenant_email TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS inspections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    property_id INTEGER,
    title TEXT,
    summary TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS photos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    inspection_id INTEGER,
    room TEXT,
    filename TEXT,
    comment TEXT
  )`);
});

/* ---------------- DEMO USERS (SAFE) ---------------- */
[
  ["admin@demo.com", "admin123", "admin"],
  ["landlord@demo.com", "landlord123", "landlord"],
  ["tenant@demo.com", "tenant123", "tenant"],
  ["inspector@demo.com", "inspector123", "inspector"],
].forEach((u) => {
  bcrypt.hash(u[1], 10, (_, hash) => {
    db.run(
      "INSERT OR IGNORE INTO users(email,password,role) VALUES(?,?,?)",
      [u[0], hash, u[2]]
    );
  });
});

/* ---------------- UPLOAD ---------------- */
const upload = multer({
  storage: multer.diskStorage({
    destination: "uploads",
    filename: (_, file, cb) =>
      cb(null, Date.now() + path.extname(file.originalname)),
  }),
});

/* ---------------- HELPERS ---------------- */
const esc = (s) =>
  String(s || "").replace(/[&<>"']/g, (m) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" }[m])
  );

const requireLogin = (req, res, next) =>
  req.session.user ? next() : res.redirect("/login");

/* ---------------- LOGIN ---------------- */
app.get("/login", (_, res) => {
  res.send(`
<link rel="stylesheet" href="/style.css">
<div class="box">
<h2>Property Management System</h2>
<form method="POST">
<input name="email" placeholder="Email" required>
<input type="password" name="password" placeholder="Password" required>
<button>Login</button>
</form>
</div>
`);
});

app.post("/login", (req, res) => {
  db.get(
    "SELECT * FROM users WHERE email=?",
    [req.body.email],
    (_, user) => {
      if (!user) return res.send("Invalid login");
      bcrypt.compare(req.body.password, user.password, (_, ok) => {
        if (!ok) return res.send("Invalid login");
        req.session.user = user;
        res.redirect("/");
      });
    }
  );
});

app.get("/logout", (req, res) =>
  req.session.destroy(() => res.redirect("/login"))
);

/* ---------------- DASHBOARD ---------------- */
app.get("/", requireLogin, (req, res) => {
  db.all("SELECT * FROM properties", (_, rows) => {
    let html = `
<link rel="stylesheet" href="/style.css">
<div class="box">
<h2>Dashboard (${esc(req.session.user.role)})</h2>
<a href="/logout">Logout</a><hr>
`;

    if (req.session.user.role !== "tenant") {
      html += `
<form method="POST" action="/add-property">
<input name="address" placeholder="Address" required>
<input name="landlord_email" placeholder="Landlord Email" required>
<input name="tenant_email" placeholder="Tenant Email">
<button>Add Property</button>
</form><hr>
`;
    }

    rows.forEach((p) => {
      if (
        req.session.user.role === "admin" ||
        p.landlord_email === req.session.user.email ||
        p.tenant_email === req.session.user.email
      ) {
        html += `<div class="card">
<b>${esc(p.address)}</b><br>
<a href="/property/${p.id}">Open</a>
</div>`;
      }
    });

    res.send(html + "</div>");
  });
});

app.post("/add-property", requireLogin, (req, res) => {
  db.run(
    "INSERT INTO properties(address,landlord_email,tenant_email) VALUES(?,?,?)",
    [req.body.address, req.body.landlord_email, req.body.tenant_email],
    () => res.redirect("/")
  );
});

/* ---------------- PROPERTY ---------------- */
app.get("/property/:id", requireLogin, (req, res) => {
  db.get(
    "SELECT * FROM properties WHERE id=?",
    [req.params.id],
    (_, p) => {
      db.all(
        "SELECT * FROM inspections WHERE property_id=?",
        [p.id],
        (_, ins) => {
          let html = `
<link rel="stylesheet" href="/style.css">
<div class="box">
<h3>${esc(p.address)}</h3>
<form method="POST" action="/add-inspection/${p.id}">
<input name="title" placeholder="Inspection title" required>
<textarea name="summary" placeholder="Summary"></textarea>
<button>Add Inspection</button>
</form><hr>
`;
          ins.forEach(
            (i) =>
              (html += `<div class="card">
${esc(i.title)} <a href="/inspection/${i.id}">Open</a>
</div>`)
          );
          res.send(html + "</div>");
        }
      );
    }
  );
});

app.post("/add-inspection/:pid", requireLogin, (req, res) => {
  db.run(
    "INSERT INTO inspections(property_id,title,summary) VALUES(?,?,?)",
    [req.params.pid, req.body.title, req.body.summary],
    () => res.redirect(`/property/${req.params.pid}`)
  );
});

/* ---------------- INSPECTION ---------------- */
app.get("/inspection/:id", requireLogin, (req, res) => {
  db.all(
    "SELECT * FROM photos WHERE inspection_id=?",
    [req.params.id],
    (_, photos) => {
      let html = `
<link rel="stylesheet" href="/style.css">
<div class="box">
<h3>Add Photo</h3>
<form method="POST" enctype="multipart/form-data" action="/add-photo/${req.params.id}">
<input name="room" placeholder="Room" required>
<input type="file" name="photo" required>
<input name="comment" placeholder="Comment">
<button>Upload</button>
</form><hr>
`;
      photos.forEach(
        (p) =>
          (html += `<img src="/uploads/${p.filename}" width="200"><br>${esc(
            p.comment
          )}<br><br>`)
      );
      res.send(html + "</div>");
    }
  );
});

app.post(
  "/add-photo/:id",
  requireLogin,
  upload.single("photo"),
  (req, res) => {
    db.run(
      "INSERT INTO photos(inspection_id,room,filename,comment) VALUES(?,?,?,?)",
      [
        req.params.id,
        req.body.room,
        req.file.filename,
        req.body.comment,
      ],
      () => res.redirect(`/inspection/${req.params.id}`)
    );
  }
);

/* ---------------- SERVER ---------------- */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log("Server running on port", PORT)
);
