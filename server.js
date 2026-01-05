const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const session = require("express-session");
const bcrypt = require("bcrypt");
const PDFDocument = require("pdfkit");

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
  // ---- CREATE DEFAULT ADMIN (RUNS ONLY ONCE) ----
db.get("SELECT * FROM users WHERE email='admin@demo.com'", (err, row) => {
  if (!row) {
    const hashed = bcrypt.hashSync("admin123", 10);
    db.run(
      "INSERT INTO users (email, password, role) VALUES (?,?,?)",
      ["admin@demo.com", hashed, "admin"],
      () => {
        console.log("✅ ADMIN READY → admin@demo.com / admin123");
      }
    );
  }
});


  // landlord_id and tenant_id let us restrict who sees what
  db.run(`CREATE TABLE IF NOT EXISTS properties (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    address TEXT,
    rooms_count INTEGER,
    amenities TEXT,
    landlord_id INTEGER,
    tenant_id INTEGER
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS inspections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    property_id INTEGER,
    title TEXT,
    summary TEXT,
    inspector_user_id INTEGER,
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
    if (!roles.includes(req.session.user.role)) return res.send("Access denied");
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

function getUserByEmail(email) {
  return new Promise((resolve) => {
    if (!email) return resolve(null);
    db.get("SELECT * FROM users WHERE email=?", [email.trim().toLowerCase()], (e, row) => {
      resolve(row || null);
    });
  });
}

/**
 * Property visibility rules:
 * - admin: can see all
 * - inspector: can see all (simple)
 * - landlord: only properties where landlord_id = user.id
 * - tenant: only properties where tenant_id = user.id
 */
function canViewProperty(user, prop) {
  if (!user || !prop) return false;
  if (user.role === "admin") return true;
  if (user.role === "inspector") return true;
  if (user.role === "landlord") return prop.landlord_id === user.id;
  if (user.role === "tenant") return prop.tenant_id === user.id;
  return false;
}

/* ---------------- AUTO-SEED USERS (first run) ---------------- */
db.get("SELECT COUNT(*) AS c FROM users", async (e, row) => {
  if (row && row.c === 0) {
    const adminPass = await bcrypt.hash("admin123", 10);
    const landlordPass = await bcrypt.hash("landlord123", 10);
    const tenantPass = await bcrypt.hash("tenant123", 10);
    const inspectorPass = await bcrypt.hash("inspector123", 10);

    db.run("INSERT INTO users(email,password,role) VALUES(?,?,?)", ["admin@demo.com", adminPass, "admin"]);
    db.run("INSERT INTO users(email,password,role) VALUES(?,?,?)", ["landlord@demo.com", landlordPass, "landlord"]);
    db.run("INSERT INTO users(email,password,role) VALUES(?,?,?)", ["tenant@demo.com", tenantPass, "tenant"]);
    db.run("INSERT INTO users(email,password,role) VALUES(?,?,?)", ["inspector@demo.com", inspectorPass, "inspector"]);

    console.log("✅ Demo users created:");
    console.log("Admin:     admin@demo.com / admin123");
    console.log("Landlord:  landlord@demo.com / landlord123");
    console.log("Tenant:    tenant@demo.com / tenant123");
    console.log("Inspector: inspector@demo.com / inspector123");
  }
});

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

  db.get("SELECT * FROM users WHERE email=?", [email.trim().toLowerCase()], (e, user) => {
    if (!user) return res.send("Invalid credentials");

    bcrypt.compare(password, user.password, (e2, ok) => {
      if (!ok) return res.send("Invalid credentials");

      req.session.user = { id: user.id, email: user.email, role: user.role };
      res.redirect("/");
    });
  });
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/login"));
});

/* ---------------- HOME (DASHBOARD) ---------------- */
app.get("/", requireLogin, (req, res) => {
  const user = req.session.user;

  let query = "SELECT * FROM properties ORDER BY id DESC";
  let params = [];

  if (user.role === "landlord") {
    query = "SELECT * FROM properties WHERE landlord_id=? ORDER BY id DESC";
    params = [user.id];
  } else if (user.role === "tenant") {
    query = "SELECT * FROM properties WHERE tenant_id=? ORDER BY id DESC";
    params = [user.id];
  }

  db.all(query, params, (e, props) => {
    let html = pageStart("Dashboard", user);

    // Add property form only for admin/landlord
    if (user.role === "admin" || user.role === "landlord") {
      html += `
<h2>Add Property</h2>
<form method="POST" action="/add-property">
  <input name="address" placeholder="Complete Address" required />
  <input name="rooms_count" type="number" placeholder="Rooms Count" required />
  <textarea name="amenities" placeholder="Amenities"></textarea>

  ${
    user.role === "admin"
      ? `
  <input name="landlord_email" placeholder="Landlord Email (required)" required />
  <input name="tenant_email" placeholder="Tenant Email (optional)" />
  `
      : `
  <input name="tenant_email" placeholder="Tenant Email (optional)" />
  `
  }

  <button>Add Property</button>
</form>
<hr/>
`;
    } else {
      html += `<p>You can only view your assigned property/properties.</p><hr/>`;
    }

    if (!props.length) html += `<p>No properties found.</p>`;

    props.forEach((p) => {
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

/* ---------------- ADD PROPERTY ---------------- */
app.post("/add-property", requireLogin, requireRole("admin", "landlord"), async (req, res) => {
  const user = req.session.user;
  const { address, rooms_count, amenities, landlord_email, tenant_email } = req.body;

  let landlordId = user.id;

  // admin must assign a landlord
  if (user.role === "admin") {
    const l = await getUserByEmail(landlord_email);
    if (!l || l.role !== "landlord") return res.send("Invalid landlord email (must be a landlord user).");
    landlordId = l.id;
  }

  let tenantId = null;
  if (tenant_email && tenant_email.trim()) {
    const t = await getUserByEmail(tenant_email);
    if (!t || t.role !== "tenant") return res.send("Invalid tenant email (must be a tenant user).");
    tenantId = t.id;
  }

  db.run(
    `INSERT INTO properties(address, rooms_count, amenities, landlord_id, tenant_id)
     VALUES(?,?,?,?,?)`,
    [address, Number(rooms_count), amenities || "", landlordId, tenantId],
    () => res.redirect("/")
  );
});

/* ---------------- PROPERTY PAGE ---------------- */
app.get("/property/:id", requireLogin, (req, res) => {
  const pid = req.params.id;
  const user = req.session.user;

  db.get("SELECT * FROM properties WHERE id=?", [pid], (e, prop) => {
    if (!prop) return res.send("Property not found");
    if (!canViewProperty(user, prop)) return res.send("Access denied");

    db.all("SELECT * FROM inspections WHERE property_id=? ORDER BY id DESC", [pid], (e2, ins) => {
      let html = pageStart("Property", user);

      html += `
<h2>${esc(prop.address)}</h2>
<p>
  <b>Rooms:</b> ${prop.rooms_count}<br/>
  <b>Amenities:</b> ${esc(prop.amenities || "-")}
</p>
<hr/>
`;

      // Add inspection only for admin/inspector
      if (user.role === "admin" || user.role === "inspector") {
        html += `
<h3>Add Inspection</h3>
<form method="POST" action="/add-inspection/${pid}">
  <input name="title" placeholder="Inspection Title" required />
  <textarea name="summary" placeholder="Inspection Summary"></textarea>
  <input name="inspection_date" type="date" />
  <button>Add Inspection</button>
</form>
<hr/>
`;
      }

      html += `<h3>Inspections</h3>`;
      if (!ins.length) html += `<p>No inspections yet.</p>`;

      ins.forEach((i) => {
        html += `
<div class="card">
  <b>${esc(i.title)}</b> (${esc(i.status || "Draft")})<br/>
  <a href="/inspection/${i.id}">Open</a> |
  <a href="/pdf/${i.id}">PDF</a>
</div>
`;
      });

      html += pageEnd();
      res.send(html);
    });
  });
});

/* ---------------- ADD INSPECTION ---------------- */
app.post("/add-inspection/:pid", requireLogin, requireRole("admin", "inspector"), (req, res) => {
  const { title, summary, inspection_date } = req.body;
  const pid = req.params.pid;
  const user = req.session.user;

  db.run(
    `INSERT INTO inspections(property_id,title,summary,inspector_user_id,inspection_date,status)
     VALUES(?,?,?,?,?,?)`,
    [pid, title, summary || "", user.id, inspection_date || "", "Draft"],
    function () {
      res.redirect(`/property/${pid}`);
    }
  );
});

/* ---------------- UPLOAD SETUP ---------------- */
const upload = multer({
  storage: multer.diskStorage({
    destination: "uploads",
    filename: (req, file, cb) => cb(null, Date.now() + "-" + Math.random().toString(16).slice(2) + path.extname(file.originalname)),
  }),
});

/* ---------------- INSPECTION PAGE ---------------- */
app.get("/inspection/:id", requireLogin, (req, res) => {
  const iid = req.params.id;
  const user = req.session.user;

  db.get(
    `SELECT i.*, p.address, p.landlord_id, p.tenant_id FROM inspections i
     JOIN properties p ON p.id = i.property_id
     WHERE i.id=?`,
    [iid],
    (e, insp) => {
      if (!insp) return res.send("Inspection not found");
      if (!canViewProperty(user, insp)) return res.send("Access denied");

      db.all("SELECT * FROM photos WHERE inspection_id=? ORDER BY room", [iid], (e2, photos) => {
        let html = pageStart("Inspection", user);

        html += `
<h2>${esc(insp.address)}</h2>
<p><b>${esc(insp.title)}</b></p>
<p>${esc(insp.summary)}</p>
<p><b>Date:</b> ${esc(insp.inspection_date || "-")}</p>
<hr/>
`;

        // Upload form only for admin/inspector
        if (user.role === "admin" || user.role === "inspector") {
          html += `
<h3>Add Photo</h3>
<form method="POST" enctype="multipart/form-data" action="/add-photo/${iid}">
  <input name="room" placeholder="Room name (e.g. Kitchen)" required />
  <input type="file" name="photo" required />
  <input name="comment" placeholder="Comment (optional)" />
  <button>Upload</button>
</form>
<hr/>
`;
        }

        // show grouped by room
        let currentRoom = "";
        photos.forEach((p) => {
          if (p.room !== currentRoom) {
            currentRoom = p.room;
            html += `<h4>${esc(currentRoom)}</h4>`;
          }
          html += `
<div style="margin-bottom:14px;">
  <img src="/uploads/${p.filename}" style="max-width:320px; width:100%; border-radius:8px; border:1px solid #ddd;"/>
  <div style="font-size:13px; margin-top:6px;">${esc(p.comment || "")}</div>
</div>
`;
        });

        html += pageEnd();
        res.send(html);
      });
    }
  );
});

/* ---------------- ADD PHOTO ---------------- */
app.post("/add-photo/:iid", requireLogin, requireRole("admin", "inspector"), upload.single("photo"), (req, res) => {
  const iid = req.params.iid;
  const { room, comment } = req.body;

  if (!req.file) return res.send("No file uploaded");

  db.run(
    "INSERT INTO photos(inspection_id,room,filename,comment) VALUES(?,?,?,?)",
    [iid, room, req.file.filename, comment || ""],
    () => res.redirect(`/inspection/${iid}`)
  );
});

/* ---------------- PDF ---------------- */
app.get("/pdf/:iid", requireLogin, (req, res) => {
  const iid = req.params.iid;
  const user = req.session.user;

  db.get(
    `SELECT i.*, p.address, p.landlord_id, p.tenant_id FROM inspections i
     JOIN properties p ON p.id = i.property_id
     WHERE i.id=?`,
    [iid],
    (e, insp) => {
      if (!insp) return res.send("Inspection not found");
      if (!canViewProperty(user, insp)) return res.send("Access denied");

      db.all("SELECT * FROM photos WHERE inspection_id=? ORDER BY room", [iid], (e2, photos) => {
        const filename = `report-${iid}.pdf`;
        const filepath = path.join(__dirname, "reports", filename);

        const doc = new PDFDocument({ margin: 40 });
        doc.pipe(fs.createWriteStream(filepath));

        doc.fontSize(18).text("Inspection Report", { align: "center" });
        doc.moveDown();

        doc.fontSize(12).text(`Property: ${insp.address}`);
        doc.text(`Title: ${insp.title}`);
        doc.text(`Date: ${insp.inspection_date || "-"}`);
        doc.moveDown();
        doc.text(`Summary: ${insp.summary || "-"}`);
        doc.moveDown();

        let currentRoom = "";
        photos.forEach((p) => {
          if (p.room !== currentRoom) {
            currentRoom = p.room;
            doc.moveDown().fontSize(14).text(`Room: ${currentRoom}`);
            doc.fontSize(12);
          }
          doc.text(`- ${p.comment || "(no comment)"}`);
        });

        doc.end();

        // redirect to the static served pdf
        setTimeout(() => {
          res.redirect(`/reports/${filename}`);
        }, 500);
      });
    }
  );
});

/* ---------------- SERVER ---------------- */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Server running on port", PORT));
