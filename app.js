"use strict";
/* CLXBank: client-side secure login using the Web Crypto API (educational demo).
   Identification, password hashing (salt + pepper), TOTP 2FA, role rules,
   AES-GCM encryption (confidentiality), HMAC (integrity), auto encrypted backups. */

const PEPPER = "9f3a6c1e5b7d482a90e4c2f817d3b65a4e0f9c28d1b7a3564c8e2f01a9d7b3e5"; // kept in code, apart from stored data
const MAX_FAILS = 5, LOCK_MS = 300000, SESSION_MS = 900000;
const DEBUG = true; // while testing: shows clock info on a wrong code. Set to false before you submit.
const PERMS = {
  user:    ["view_own_balance"],
  manager: ["view_own_balance", "view_all_balances"],
  admin:   ["view_own_balance", "view_all_balances", "manage_users"],
};

const S = crypto.subtle, enc = new TextEncoder(), dec = new TextDecoder();
const $ = id => document.getElementById(id);
const say = t => { $("msg").textContent = t; };
const show = id => document.querySelectorAll("section.card").forEach(s => s.hidden = s.id !== id);
const b64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
const rnd = n => crypto.getRandomValues(new Uint8Array(n));
const eq = (a, b) => { // constant-time string comparison
  if (a.length !== b.length) return false;
  let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
};

let db, KEYS, session = null, pending = null, backupTimer;

/* ---------- Storage ---------- */
function load() {
  try { db = JSON.parse(localStorage.getItem("CLXBank")); } catch (e) { db = null; }
  if (!db) db = { salt: b64(rnd(16)), users: {}, audit: [] };
}
function save() {
  try { localStorage.setItem("CLXBank", JSON.stringify(db)); } catch (e) { say("Storage error"); }
  clearTimeout(backupTimer); backupTimer = setTimeout(() => backup("auto"), 2000);
}
const getBackups = () => { try { return JSON.parse(localStorage.getItem("CLXBank_backups")) || []; } catch (e) { return []; } };

/* ---------- Cryptography ---------- */
async function hmac(keyBytes, data) {
  const k = await S.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await S.sign("HMAC", k, data));
}
// Password hash: HMAC with pepper, then PBKDF2 (slow) with a per-user salt
async function hashPw(pw, salt) {
  const peppered = await hmac(enc.encode(PEPPER), enc.encode(pw));
  const k = await S.importKey("raw", peppered, "PBKDF2", false, ["deriveBits"]);
  return hex(await S.deriveBits({ name: "PBKDF2", salt, iterations: 210000, hash: "SHA-256" }, k, 256));
}
// Separate keys for encryption (AES-GCM) and integrity (HMAC), derived with PBKDF2 + HKDF
async function makeKeys(saltB64) {
  const base = await S.importKey("raw", enc.encode(PEPPER), "PBKDF2", false, ["deriveBits"]);
  const master = await S.deriveBits({ name: "PBKDF2", salt: unb64(saltB64), iterations: 100000, hash: "SHA-256" }, base, 256);
  const hk = await S.importKey("raw", master, "HKDF", false, ["deriveKey"]);
  const derive = (info, alg, use) => S.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(), info: enc.encode(info) }, hk, alg, false, use);
  return {
    aes: await derive("enc", { name: "AES-GCM", length: 256 }, ["encrypt", "decrypt"]),
    mac: await derive("mac", { name: "HMAC", hash: "SHA-256" }, ["sign", "verify"]),
  };
}
// AES-256-GCM: confidentiality + built-in integrity tag; aad binds a record to its owner
async function seal(obj, keys = KEYS, aad) {
  const iv = rnd(12), p = { name: "AES-GCM", iv };
  if (aad) p.additionalData = enc.encode(aad);
  return { iv: b64(iv), ct: b64(await S.encrypt(p, keys.aes, enc.encode(JSON.stringify(obj)))) };
}
async function open(box, keys = KEYS, aad) {
  const p = { name: "AES-GCM", iv: unb64(box.iv) };
  if (aad) p.additionalData = enc.encode(aad);
  return JSON.parse(dec.decode(await S.decrypt(p, keys.aes, unb64(box.ct)))); // throws if tampered
}

/* ---------- TOTP (RFC 6238, HMAC-SHA1, 6 digits, 30 s) ---------- */
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function b32enc(bytes) {
  let bits = "", out = "";
  for (const b of bytes) bits += b.toString(2).padStart(8, "0");
  for (let i = 0; i < bits.length; i += 5) out += B32[parseInt(bits.slice(i, i + 5).padEnd(5, "0"), 2)];
  return out;
}
function b32dec(s) {
  let bits = "", out = [];
  for (const c of s) bits += B32.indexOf(c).toString(2).padStart(5, "0");
  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
  return new Uint8Array(out);
}
async function totp(secret, counter) {
  const k = await S.importKey("raw", b32dec(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const msg = new DataView(new ArrayBuffer(8)); msg.setUint32(4, counter);
  const h = new Uint8Array(await S.sign("HMAC", k, msg.buffer)), o = h[19] & 15;
  const n = (((h[o] & 127) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3]) % 1e6;
  return String(n).padStart(6, "0");
}
async function checkTotp(secret, code) {
  const t = Math.floor(Date.now() / 30000);
  for (const d of [-1, 0, 1]) if (await totp(secret, t + d) === code) return true; // 1 step of clock drift
  return false;
}

/* ---------- Tamper-evident audit log (hash-chained HMAC) ---------- */
async function log(user, event) {
  const prev = db.audit.length ? db.audit[db.audit.length - 1].mac : "";
  const e = { ts: Date.now(), user, event };
  e.mac = b64(await S.sign("HMAC", KEYS.mac, enc.encode(prev + JSON.stringify(e))));
  db.audit.push(e); save();
}
async function verifyAudit() {
  let prev = "";
  for (let i = 0; i < db.audit.length; i++) {
    const { ts, user, event, mac } = db.audit[i];
    const ok = await S.verify("HMAC", KEYS.mac, unb64(mac), enc.encode(prev + JSON.stringify({ ts, user, event })));
    if (!ok) return say(`INTEGRITY FAILURE: audit log modified at entry ${i + 1}`);
    prev = mac;
  }
  say(`Audit log verified: ${db.audit.length} entries intact`);
}

/* ---------- Encrypted, integrity-protected backups ---------- */
async function backup(kind) {
  if (!Object.keys(db.users).length) return null;
  const box = await seal(db);                                   // confidentiality
  const mac = b64(await S.sign("HMAC", KEYS.mac, enc.encode(db.salt + box.iv + box.ct))); // integrity
  const env = { v: 1, ts: Date.now(), kind, salt: db.salt, ...box, mac };
  try { localStorage.setItem("CLXBank_backups", JSON.stringify([...getBackups(), env].slice(-5))); } catch (e) {}
  return env;
}
async function restore(env) {
  const k = await makeKeys(env.salt);
  const ok = await S.verify("HMAC", k.mac, unb64(env.mac), enc.encode(env.salt + env.iv + env.ct));
  if (!ok) throw new Error("INTEGRITY CHECK FAILED: backup was modified or is not from this system. Nothing restored.");
  const restored = await open(env, k);
  db = restored; KEYS = k;
  localStorage.setItem("CLXBank", JSON.stringify(db));
}

/* ---------- Rules: authentication + authorisation ---------- */
const strong = p => p.length >= 10 && /[a-z]/.test(p) && /[A-Z]/.test(p) && /\d/.test(p) && /[^\w\s]/.test(p);
async function need(perm) {
  if (!session || Date.now() > session.exp) { session = null; show("s-login"); say("Login required"); return false; }
  if (!PERMS[session.role].includes(perm)) { await log(session.user, "DENIED " + perm); say("Forbidden: your role lacks this permission"); return false; }
  return true;
}

/* ---------- Actions ---------- */
async function register() {
  const u = $("ru").value.trim(), p = $("rp").value;
  if (!/^[A-Za-z0-9_]{3,30}$/.test(u)) return say("Username must be 3 to 30 characters: only letters, numbers and _ (no spaces, @, - or .)");
  if (!strong(p)) return say("Password too weak: it needs 10+ characters with an upper case letter, a lower case letter, a number and a symbol");
  if (db.users[u]) return say("Username unavailable");
  const salt = rnd(16), secret = b32enc(rnd(20)), first = !Object.keys(db.users).length;
  db.users[u] = {
    salt: b64(salt), hash: await hashPw(p, salt), role: first ? "admin" : "user",
    rec: await seal({ balance: 1000, totp: secret }, KEYS, u), fails: 0, lock: 0,
  };
  await log(u, "REGISTER");
  $("rp").value = ""; $("setup").hidden = false;
  $("key").textContent = secret.match(/.{4}/g).join(" ");
  $("uri").textContent = `otpauth://totp/CLXBank:${u}?secret=${secret}&issuer=CLXBank`;
  say("Registered. Add the setup key to your authenticator app, then log in.");
}
async function login() {
  const u = $("lu").value.trim(), p = $("lp").value, r = db.users[u];
  if (r && r.lock > Date.now()) return say("Account temporarily locked");
  const h = await hashPw(p, r ? unb64(r.salt) : rnd(16));       // dummy work if user unknown
  if (!(r && eq(h, r.hash))) {
    if (r) { r.fails++; if (r.fails >= MAX_FAILS) { r.lock = Date.now() + LOCK_MS; r.fails = 0; } save(); }
    await log(u, "LOGIN_FAIL");
    return say("Invalid credentials");                          // same message in both cases
  }
  r.fails = 0; save(); $("lp").value = "";
  pending = { u, at: Date.now() }; show("s-2fa"); say("Password OK. Enter your authenticator code.");
}
async function verify() {
  if (!pending || Date.now() - pending.at > 120000) { pending = null; show("s-login"); return say("Start again"); }
  const r = db.users[pending.u]; let rec;
  try { rec = await open(r.rec, KEYS, pending.u); }
  catch (e) { return say("INTEGRITY FAILURE: this user record was tampered with"); }
  const code = $("code").value.replace(/\D/g, "");               // ignore spaces, e.g. "123 456"
  if (!(await checkTotp(rec.totp, code))) {
    await log(pending.u, "2FA_FAIL");
    if (DEBUG) {
      const t = Math.floor(Date.now() / 30000);
      const exp = await Promise.all([-1, 0, 1].map(d => totp(rec.totp, t + d)));
      console.log("DEBUG you typed:", code, "| site expects one of:", exp.join(", "), "| computer time:", new Date().toString());
    }
    return say(`Invalid code. This computer's clock says ${new Date().toLocaleTimeString()}; it must match your phone's time within 30 seconds.`);
  }
  session = { user: pending.u, role: r.role, exp: Date.now() + SESSION_MS };
  pending = null; $("code").value = ""; await log(session.user, "LOGIN_OK"); home();
}
async function home() {
  show("s-home"); say("Logged in");
  $("who").textContent = `${session.user} (${session.role})`; $("list").textContent = "";
  try { $("bal").textContent = "Your balance: " + (await open(db.users[session.user].rec, KEYS, session.user)).balance; }
  catch (e) { $("bal").textContent = "Record failed integrity check"; }
  $("btn-all").hidden = !PERMS[session.role].includes("view_all_balances");
  $("admin").hidden = !PERMS[session.role].includes("manage_users");
  if (!$("admin").hidden) renderAdmin();
}
async function allBalances() {
  if (!(await need("view_all_balances"))) return;
  const ul = $("list"); ul.textContent = "";
  for (const [u, r] of Object.entries(db.users)) {
    const li = document.createElement("li");
    try { li.textContent = `${u}: ${(await open(r.rec, KEYS, u)).balance}`; } catch (e) { li.textContent = `${u}: INTEGRITY ERROR`; }
    ul.appendChild(li);
  }
}
function renderAdmin() {
  const box = $("users"); box.textContent = "";
  for (const [u, r] of Object.entries(db.users)) {
    const row = document.createElement("div"), name = document.createElement("span"), sel = document.createElement("select");
    row.className = "row"; name.textContent = u;
    Object.keys(PERMS).forEach(role => sel.add(new Option(role, role))); sel.value = r.role;
    sel.onchange = async () => {
      if (!(await need("manage_users"))) return;
      r.role = sel.value; save(); await log(session.user, `ROLE ${u}->${sel.value}`); say("Role updated"); renderAdmin();
    };
    row.append(name, sel); box.appendChild(row);
  }
  const b = getBackups();
  $("backups").textContent = b.length ? b.map(x => `${new Date(x.ts).toLocaleTimeString()} (${x.kind})`).join("  |  ") : "No backups yet";
  $("audit").textContent = db.audit.slice(-8).map(e => `${new Date(e.ts).toLocaleTimeString()}  ${e.user}  ${e.event}`).join("\n");
}
async function doRestore(env) {
  if (!(await need("manage_users"))) return;
  try { await restore(env); session = null; show("s-login"); say("Backup restored: integrity verified. Please log in again."); }
  catch (e) { say(e.message.startsWith("INTEGRITY") ? e.message : "Restore failed: backup could not be decrypted"); }
}

/* ---------- Wiring ---------- */
// show the real error message in the blue box instead of failing silently
const safe = fn => async () => { try { await fn(); } catch (e) { console.error(e); say("Error: " + e.message); } };
$("go-login").onclick = safe(login);
$("go-reg").onclick = safe(register);
$("go-2fa").onclick = safe(verify);
$("btn-all").onclick = allBalances;
$("to-reg").onclick = () => { show("s-reg"); $("setup").hidden = true; };
$("to-login").onclick = () => show("s-login");
$("logout").onclick = async () => { await log(session.user, "LOGOUT"); session = null; show("s-login"); say("Logged out"); };
$("a-verify").onclick = async () => { if (await need("manage_users")) verifyAudit(); };
$("b-now").onclick = async () => { if (!(await need("manage_users"))) return; await backup("manual"); renderAdmin(); say("Encrypted backup created"); };
$("b-dl").onclick = async () => {
  if (!(await need("manage_users"))) return;
  const env = await backup("download"), a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([JSON.stringify(env)], { type: "application/json" }));
  a.download = "CLXBank-backup-" + new Date().toISOString().replace(/[:.]/g, "-") + ".json";
  a.click(); URL.revokeObjectURL(a.href); renderAdmin(); say("Backup file downloaded (encrypted)");
};
$("b-restore").onclick = () => { const b = getBackups(); b.length ? doRestore(b[b.length - 1]) : say("No backups available"); };
$("b-file").onchange = async e => {
  try { await doRestore(JSON.parse(await e.target.files[0].text())); } catch (err) { say("Invalid backup file"); }
  e.target.value = "";
};
$("b-tamper").onclick = async () => {
  if (!(await need("manage_users"))) return;
  const b = getBackups(); if (!b.length) return say("Make a backup first");
  const x = b[b.length - 1]; x.ct = x.ct.slice(0, -4) + (x.ct.slice(-4) === "AAAA" ? "BBBB" : "AAAA");
  localStorage.setItem("CLXBank_backups", JSON.stringify(b));
  say("Latest backup corrupted on purpose. Now click 'Restore latest backup' to see the integrity check fail.");
};

(async () => {
  if (!crypto.subtle) return say("Web Crypto unavailable: open this page from http://localhost or file:// in Chrome/Edge.");
  load(); KEYS = await makeKeys(db.salt); show("s-login");
  setInterval(() => backup("auto"), 30000);                                  // automatic periodic backup
  setInterval(() => { if (session && Date.now() > session.exp) { session = null; show("s-login"); say("Session expired"); } }, 5000);
})();
