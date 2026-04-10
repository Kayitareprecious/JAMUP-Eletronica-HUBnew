import express from "express";
import Database from "better-sqlite3";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cors from "cors";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || "jamup-secret-key-2024-rwanda";

const ALLOWED_ADMIN_EMAILS = [
  "jabojulesmaurice@gmail.com",
  "gasnamoses01@gmail.com",
  "uwingabireange2003@gmail.com",
  "uwajenezaernestine2002@gmail.com",
  "kayitareprecious057@gmail.com",
];

const db = new Database("jamup.db");

db.exec(`
  CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    registered_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS bookings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    phone TEXT NOT NULL,
    customer_email TEXT,
    device_type TEXT NOT NULL,
    issue TEXT NOT NULL,
    location TEXT,
    preferred_hour TEXT,
    status TEXT DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS page_visits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    path TEXT NOT NULL,
    ip TEXT,
    user_agent TEXT,
    visited_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

app.use(cors({ origin: true, credentials: true }));
app.use(express.json());

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.replace("Bearer ", "");
  if (!token) return res.status(401).json({ error: "No token" });
  try {
    req.admin = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
}

// Track page visits
app.post("/api/track-visit", (req, res) => {
  const { path: visitPath } = req.body;
  const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "unknown";
  const ua = req.headers["user-agent"] || "";
  db.prepare("INSERT INTO page_visits (path, ip, user_agent) VALUES (?, ?, ?)").run(visitPath || "/", ip, ua);
  res.json({ ok: true });
});

// Submit booking
app.post("/api/book-repair", (req, res) => {
  const { name, phone, deviceType, issue, customerEmail, location, preferredHour } = req.body;
  if (!name || !phone || !deviceType || !issue) {
    return res.status(400).json({ error: "Missing required fields." });
  }
  const stmt = db.prepare(`
    INSERT INTO bookings (name, phone, customer_email, device_type, issue, location, preferred_hour)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);
  const result = stmt.run(name, phone, customerEmail || null, deviceType, issue, location || null, preferredHour || null);
  res.json({ ok: true, id: result.lastInsertRowid });
});

// Get bookings for user portal (public)
app.get("/api/bookings", (req, res) => {
  const bookings = db.prepare("SELECT * FROM bookings ORDER BY created_at DESC").all();
  res.json({ bookings });
});

// ADMIN: Check if email is allowed
app.post("/api/admin/check-email", (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email required" });
  const normalized = email.toLowerCase().trim();
  const allowed = ALLOWED_ADMIN_EMAILS.includes(normalized);
  const existing = db.prepare("SELECT id FROM admins WHERE email = ?").get(normalized);
  res.json({ allowed, registered: !!existing });
});

// ADMIN: Register
app.post("/api/admin/register", (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ error: "All fields required." });
  }
  const normalized = email.toLowerCase().trim();
  if (!ALLOWED_ADMIN_EMAILS.includes(normalized)) {
    return res.status(403).json({ error: "Your email is not authorized as an admin. Contact the JAMUP team." });
  }
  const existing = db.prepare("SELECT id FROM admins WHERE email = ?").get(normalized);
  if (existing) {
    return res.status(409).json({ error: "This email is already registered as an admin." });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: "Password must be at least 6 characters." });
  }
  const hash = bcrypt.hashSync(password, 10);
  db.prepare("INSERT INTO admins (name, email, password_hash) VALUES (?, ?, ?)").run(name, normalized, hash);
  const token = jwt.sign({ email: normalized, name }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ ok: true, token, name, email: normalized });
});

// ADMIN: Login
app.post("/api/admin/login", (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Email and password required." });
  const normalized = email.toLowerCase().trim();
  if (!ALLOWED_ADMIN_EMAILS.includes(normalized)) {
    return res.status(403).json({ error: "You do not have access. This system is for authorized JAMUP admins only." });
  }
  const admin = db.prepare("SELECT * FROM admins WHERE email = ?").get(normalized);
  if (!admin) return res.status(404).json({ error: "No admin account found for this email. Please register first." });
  const valid = bcrypt.compareSync(password, admin.password_hash);
  if (!valid) return res.status(401).json({ error: "Incorrect password." });
  const token = jwt.sign({ email: normalized, name: admin.name, id: admin.id }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ ok: true, token, name: admin.name, email: normalized });
});

// ADMIN: Dashboard data
app.get("/api/admin/clients", authMiddleware, (req, res) => {
  const bookings = db.prepare("SELECT * FROM bookings ORDER BY created_at DESC").all();
  const admins = db.prepare("SELECT id, name, email, registered_at FROM admins ORDER BY registered_at DESC").all();
  res.json({ bookings, admins });
});

// ADMIN: Update booking status
app.patch("/api/admin/bookings/:id/status", authMiddleware, (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  const validStatuses = ["pending", "in_progress", "completed", "cancelled", "denied"];
  if (!validStatuses.includes(status)) return res.status(400).json({ error: "Invalid status" });
  db.prepare("UPDATE bookings SET status = ? WHERE id = ?").run(status, id);
  res.json({ ok: true });
});

// ADMIN: Analytics
app.get("/api/admin/analytics", authMiddleware, (req, res) => {
  const totalBookings = db.prepare("SELECT COUNT(*) as count FROM bookings").get().count;
  const totalVisits = db.prepare("SELECT COUNT(*) as count FROM page_visits").get().count;
  const todayVisits = db.prepare("SELECT COUNT(*) as count FROM page_visits WHERE date(visited_at) = date('now')").get().count;
  const bookingsByStatus = db.prepare("SELECT status, COUNT(*) as count FROM bookings GROUP BY status").all();
  const bookingsByDevice = db.prepare("SELECT device_type, COUNT(*) as count FROM bookings GROUP BY device_type ORDER BY count DESC").all();
  const bookingsByLocation = db.prepare("SELECT location, COUNT(*) as count FROM bookings WHERE location IS NOT NULL AND location != '' GROUP BY location ORDER BY count DESC LIMIT 10").all();
  const bookingsPerDay = db.prepare(`
    SELECT date(created_at) as day, COUNT(*) as count
    FROM bookings
    WHERE created_at >= date('now', '-30 days')
    GROUP BY date(created_at)
    ORDER BY day ASC
  `).all();
  const visitsPerDay = db.prepare(`
    SELECT date(visited_at) as day, COUNT(*) as count
    FROM page_visits
    WHERE visited_at >= date('now', '-30 days')
    GROUP BY date(visited_at)
    ORDER BY day ASC
  `).all();
  const totalClients = db.prepare("SELECT COUNT(DISTINCT phone) as count FROM bookings").get().count;
  const totalAdmins = db.prepare("SELECT COUNT(*) as count FROM admins").get().count;

  res.json({
    totalBookings,
    totalVisits,
    todayVisits,
    totalClients,
    totalAdmins,
    bookingsByStatus,
    bookingsByDevice,
    bookingsByLocation,
    bookingsPerDay,
    visitsPerDay,
  });
});

// Serve built frontend in production
const distPath = path.join(__dirname, "dist");
app.use(express.static(distPath));

// Catch-all: send index.html for any non-API route (client-side routing)
app.get("/{*splat}", (req, res) => {
  res.sendFile(path.join(distPath, "index.html"));
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`JAMUP API server running on http://localhost:${PORT}`);
});
