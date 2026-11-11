require("dotenv").config();
const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const nodemailer = require("nodemailer");

const app = express();

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || "smtp.gmail.com",
  port: Number(process.env.SMTP_PORT || 465),
  secure: true,
  auth: {
    user: process.env.SMTP_USER || "osintcore@gmail.com",
    pass: process.env.SMTP_PASS
  }
});

const PORT = Number(process.env.PORT || 3000);
const isProd = process.env.NODE_ENV === "production";
const publicOrigin = process.env.PUBLIC_ORIGIN || `http://localhost:${PORT}`;
const dataDir = path.join(__dirname, "data");
fs.mkdirSync(dataDir, { recursive: true });

if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  console.error("SESSION_SECRET must be set to a random value of at least 32 characters.");
  process.exit(1);
}
if (!process.env.HCAPTCHA_SITEKEY || !process.env.HCAPTCHA_SECRET) {
  console.warn("hCaptcha keys are missing. Registration/login verification will fail until configured.");
}

app.disable("x-powered-by");
if (isProd) app.set("trust proxy", 1);
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "https://js.hcaptcha.com"],
      frameSrc: ["https://hcaptcha.com", "https://*.hcaptcha.com"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      connectSrc: ["'self'", "https://hcaptcha.com", "https://*.hcaptcha.com"],
      imgSrc: ["'self'", "data:", "https://*.hcaptcha.com"],
      fontSrc: ["'self'", "data:"]
    }
  }
}));
app.use(express.json({ limit: "20kb" }));
app.use(express.urlencoded({ extended: false, limit: "20kb" }));

app.use(session({
  name: "osintcore.sid",
  store: new SQLiteStore({ db: "sessions.sqlite", dir: dataDir }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    secure: isProd,
    sameSite: "strict",
    maxAge: 1000 * 60 * 60 * 8
  }
}));

const Database = require("better-sqlite3");
const db = new Database(path.join(dataDir, "osintcore.sqlite"));
db.pragma("journal_mode = WAL");
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    is_verified INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS verifications (
    email TEXT PRIMARY KEY,
    code TEXT NOT NULL,
    expires_at INTEGER NOT NULL
  );
`);

const findUser = db.prepare("SELECT id, email, password_hash, is_verified FROM users WHERE email = ?");
const createUser = db.prepare("INSERT INTO users (email, password_hash, is_verified) VALUES (?, ?, 0)");
const setVerified = db.prepare("UPDATE users SET is_verified = 1 WHERE email = ?");
const saveVerificationCode = db.prepare("INSERT OR REPLACE INTO verifications (email, code, expires_at) VALUES (?, ?, ?)");
const getVerificationCode = db.prepare("SELECT code, expires_at FROM verifications WHERE email = ?");
const deleteVerificationCode = db.prepare("DELETE FROM verifications WHERE email = ?");

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "Çok fazla deneme yapıldı. Bir süre sonra tekrar dene." }
});

function originGuard(req, res, next) {
  const origin = req.get("origin");
  if (origin && origin !== publicOrigin) return res.status(403).json({ error: "Origin doğrulanamadı." });
  next();
}
function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: "Devam etmek için giriş yap." });
  next();
}
async function verifyCaptcha(token, remoteip) {
  if (!process.env.HCAPTCHA_SECRET || !token) return false;
  const body = new URLSearchParams({
    secret: process.env.HCAPTCHA_SECRET,
    response: token
  });
  if (remoteip) body.set("remoteip", remoteip);
  try {
    const response = await fetch("https://api.hcaptcha.com/siteverify", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body
    });
    const result = await response.json();
    return Boolean(result.success);
  } catch {
    return false;
  }
}

app.get("/config.js", (req, res) => {
  res.type("application/javascript").set("Cache-Control", "no-store")
    .send(`window.OSINTCORE_CONFIG = ${JSON.stringify({ hcaptchaSitekey: process.env.HCAPTCHA_SITEKEY || "" })};`);
});

app.post("/api/register", authLimiter, originGuard, async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  const captchaToken = String(req.body.captchaToken || "");
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254)
    return res.status(400).json({ error: "Geçerli bir e-posta adresi gir." });
  if (password.length < 12 || password.length > 128)
    return res.status(400).json({ error: "Şifre 12–128 karakter arasında olmalı." });
  if (!await verifyCaptcha(captchaToken, req.ip))
    return res.status(400).json({ error: "hCaptcha doğrulaması başarısız. Tekrar dene." });
  try {
    const hash = await bcrypt.hash(password, 12);
    try {
      createUser.run(email, hash);
    } catch (e) {
      if (String(e.code).includes("SQLITE_CONSTRAINT")) {
        return res.status(409).json({ error: "Bu e-posta zaten kayıtlı." });
      }
      throw e;
    }

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = Date.now() + 10 * 60 * 1000;
    saveVerificationCode.run(email, code, expiresAt);

    await transporter.sendMail({
      from: `"OSINTCORE Security" <${process.env.SMTP_USER || "osintcore@gmail.com"}>`,
      to: email,
      subject: "OSINTCORE - Hesap Doğrulama Kodun",
      text: `Merhaba,\n\nOSINTCORE hesabını doğrulamak için gereken doğrulama kodun: ${code}\n\nBu kod 10 dakika geçerlidir.`
    });

    res.status(200).json({ requireVerification: true, email, message: "Doğrulama kodu osintcore@gmail.com üzerinden e-posta adresine gönderildi." });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Kayıt veya e-posta gönderimi başarısız oldu." });
  }
});

app.post("/api/verify-code", authLimiter, originGuard, async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const code = String(req.body.code || "").trim();
  const record = getVerificationCode.get(email);
  if (!record || record.code !== code || Date.now() > record.expires_at) {
    return res.status(400).json({ error: "Geçersiz veya süresi dolmuş doğrulama kodu." });
  }
  setVerified.run(email);
  deleteVerificationCode.run(email);
  const user = findUser.get(email);
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: "Oturum başlatılamadı." });
    req.session.user = { id: user.id, email: user.email };
    req.session.save(saveErr => {
      if (saveErr) return res.status(500).json({ error: "Oturum kaydedilemedi." });
      res.json({ user: req.session.user });
    });
  });
});

app.post("/api/login", authLimiter, originGuard, async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  const captchaToken = String(req.body.captchaToken || "");
  if (!await verifyCaptcha(captchaToken, req.ip))
    return res.status(400).json({ error: "hCaptcha doğrulaması başarısız. Tekrar dene." });
  const user = findUser.get(email);
  if (!user || !await bcrypt.compare(password, user.password_hash))
    return res.status(401).json({ error: "E-posta veya şifre hatalı." });
  
  if (user.is_verified === 0) {
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = Date.now() + 10 * 60 * 1000;
    saveVerificationCode.run(email, code, expiresAt);
    await transporter.sendMail({
      from: `"OSINTCORE Security" <${process.env.SMTP_USER || "osintcore@gmail.com"}>`,
      to: email,
      subject: "OSINTCORE - Hesap Doğrulama Kodun",
      text: `Hesabınız henüz doğrulanmamış. Doğrulama kodunuz: ${code}`
    });
    return res.status(403).json({ requireVerification: true, email, error: "Hesabınız doğrulanmamış. osintcore@gmail.com üzerinden yeni doğrulama kodu gönderildi." });
  }

  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: "Oturum başlatılamadı." });
    req.session.user = { id: user.id, email: user.email };
    req.session.save(saveErr => {
      if (saveErr) return res.status(500).json({ error: "Oturum kaydedilemedi." });
      res.json({ user: req.session.user });
    });
  });
});

app.get("/api/me", (req, res) => res.json({ user: req.session.user || null }));
app.post("/api/logout", originGuard, requireAuth, (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).json({ error: "Çıkış yapılamadı." });
    res.clearCookie("osintcore.sid", { httpOnly: true, sameSite: "strict", secure: isProd });
    res.json({ ok: true });
  });
});

app.get("/api/workspace", requireAuth, (req, res) => {
  res.json({
    user: req.session.user,
    modules: ["Discord", "Instagram", "YouTube", "TikTok"],
    notice: "Yalnızca herkese açık ve izinli araştırma. Platform veri entegrasyonları henüz bağlanmadı."
  });
});

app.use(express.static(path.join(__dirname, "public"), { extensions: ["html"] }));
app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

app.listen(PORT, () => console.log(`OSINTCORE is running at ${publicOrigin}`));
