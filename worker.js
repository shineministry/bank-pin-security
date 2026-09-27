/* security2 - encrypted PIN / pushTAN vault
 * Cloudflare Worker: static UI + JSON API.
 *
 * Secrets (set with `wrangler secret put NAME`):
 *   AUTH_PASSWORD     master password used to unlock the vault
 *   VAULT_KEY         random 32+ byte key used to AES-GCM encrypt data at rest
 *   BANK_PIN          debit card PIN, served read-only to an authenticated session
 *   PUSHTAN           pushTAN value, served read-only to an authenticated session
 *   GATE_NAME         expected full name for step 1 of the unlock
 *   GATE_EMAIL        expected e-mail address
 *   GATE_DOB          expected date of birth (YYYY-MM-DD or DD-MM-YYYY)
 *   CONFIRMATION_ID   confirmation ID issued by Shineil
 */

const GATE_COOKIE = "__Host-gate_sid";
const VAULT_COOKIE = "__Host-vault_sid";

const GATE_PREFIX = "gsess:";
const VAULT_PREFIX = "sess:";

const SESSION_TTL = 3600; // seconds, sliding
const ATTEMPT_WINDOW = 900;
const MAX_ATTEMPTS = 5;
const MAX_BODY = 65536;
const MAX_ENTRIES = 200;
const MAX_LABEL = 64;
const MAX_VALUE = 256;
const KINDS = ["pin", "pushtan", "note"];
const ID_RE = /^[A-Za-z0-9_-]{8,64}$/;
const SECRET_ID = /^secret-/;

const CSP_LOCKDOWN =
  "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

const BASE_HEADERS = {
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "X-Robots-Tag": "noindex, nofollow, noarchive, noimageindex",
  "Cache-Control": "no-store, no-cache, must-revalidate, private",
  Pragma: "no-cache",
  "Permissions-Policy":
    "accelerometer=(), autoplay=(), camera=(), display-capture=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), usb=(), xr-spatial-tracking=()",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Cross-Origin-Embedder-Policy": "require-corp",
  "Content-Security-Policy": CSP_LOCKDOWN,
};

/* ---------------------------------------------------------------- helpers */

const te = new TextEncoder();

function bytesToB64(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function b64ToBytes(str) {
  const s = atob(str);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

function randomToken(bytes) {
  return bytesToB64(crypto.getRandomValues(new Uint8Array(bytes)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function sha256(buf) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", buf));
}

/** Length-independent comparison of two strings. */
async function safeEqual(a, b) {
  const [x, y] = await Promise.all([sha256(te.encode(a)), sha256(te.encode(b))]);
  let diff = 0;
  for (let i = 0; i < 32; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

function json(data, status = 200, extra = {}) {
  const headers = new Headers(BASE_HEADERS);
  headers.set("Content-Type", "application/json; charset=utf-8");
  const cookies = extra["Set-Cookie"];
  for (const [k, v] of Object.entries(extra)) {
    if (k !== "Set-Cookie") headers.set(k, v);
  }
  // Set-Cookie must be a real header per value - never comma-joined.
  if (Array.isArray(cookies)) for (const c of cookies) headers.append("Set-Cookie", c);
  else if (cookies) headers.set("Set-Cookie", cookies);
  return new Response(JSON.stringify(data), { status, headers });
}

function text(body, status, extra = {}) {
  return new Response(body, { status, headers: { ...BASE_HEADERS, ...extra } });
}

function readCookie(request, name) {
  const header = request.headers.get("Cookie");
  if (!header) return null;
  for (const part of header.split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i).trim() === name) {
      return decodeURIComponent(part.slice(i + 1).trim());
    }
  }
  return null;
}

function sessionCookie(name, value, maxAge) {
  return `${name}=${encodeURIComponent(value)}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Strict`;
}

async function readJson(request) {
  const declared = Number(request.headers.get("content-length") || 0);
  if (declared > MAX_BODY) throw new Error("payload too large");
  const raw = await request.text();
  if (raw.length > MAX_BODY) throw new Error("payload too large");
  return JSON.parse(raw);
}

/** Reject cross-site requests that somehow carry a valid session cookie. */
function sameOrigin(request) {
  const site = request.headers.get("Sec-Fetch-Site");
  if (site && site !== "same-origin" && site !== "none") return false;
  const origin = request.headers.get("Origin");
  if (origin && origin !== new URL(request.url).origin) return false;
  return true;
}

function clientIp(request) {
  return request.headers.get("cf-connecting-ip") || "unknown";
}

/* ------------------------------------------------------------ storage (DO) */

/**
 * Single-writer key/value store backed by a SQLite Durable Object.
 * No namespace has to be provisioned: the binding is created by the
 * migration block in wrangler.toml on the first deploy.
 */
export class VaultStore {
  constructor(ctx, env) {
    this.state = ctx;
  }

  async kvGet(key) {
    const v = await this.state.storage.get(key);
    return v === undefined ? null : v;
  }

  async kvPut(key, value, opts) {
    const o = {};
    const ttl = opts && Number(opts.expirationTtl);
    if (Number.isFinite(ttl) && ttl > 0) o.expirationTtl = Math.max(60, Math.floor(ttl));
    await this.state.storage.put(key, value, o);
  }

  async kvDelete(key) {
    await this.state.storage.delete(key);
  }
}

async function store(env) {
  if (!env.VAULT || typeof env.VAULT.idFromName !== "function") {
    throw new Error("VAULT binding missing");
  }
  return env.VAULT.get(env.VAULT.idFromName("main"));
}

const kvGet = async (env, key) => (await store(env)).kvGet(key);
const kvPut = async (env, key, value, opts) => (await store(env)).kvPut(key, value, opts || {});
const kvDel = async (env, key) => (await store(env)).kvDelete(key);

/* ------------------------------------------------------------- encryption */

async function vaultKey(env) {
  if (!env.VAULT_KEY) throw new Error("VAULT_KEY missing");
  return crypto.subtle.importKey(
    "raw",
    await sha256(te.encode(env.VAULT_KEY)),
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  );
}

async function seal(key, value) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, te.encode(JSON.stringify(value)))
  );
  const packed = new Uint8Array(iv.length + ct.length);
  packed.set(iv, 0);
  packed.set(ct, iv.length);
  return bytesToB64(packed);
}

async function unseal(key, blob) {
  const raw = b64ToBytes(blob);
  if (raw.length < 13) throw new Error("corrupt");
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: raw.slice(0, 12) },
    key,
    raw.slice(12)
  );
  return JSON.parse(new TextDecoder().decode(plain));
}

/* ---------------------------------------------------------- session store */

async function createSession(env, prefix) {
  const sid = randomToken(32);
  const exp = Math.floor(Date.now() / 1000) + SESSION_TTL;
  await kvPut(env, prefix + sid, JSON.stringify({ exp }), { expirationTtl: SESSION_TTL + 60 });
  return sid;
}

async function lookupSession(request, env, cookieName, prefix) {
  const sid = readCookie(request, cookieName);
  if (!sid || sid.length < 40 || sid.length > 100) return null;
  const raw = await kvGet(env, prefix + sid);
  if (!raw) return null;

  let rec;
  try {
    rec = JSON.parse(raw);
  } catch {
    return null;
  }

  const now = Math.floor(Date.now() / 1000);
  if (!rec || typeof rec.exp !== "number" || rec.exp <= now) {
    await kvDel(env, prefix + sid);
    return null;
  }

  // Sliding renewal, throttled to avoid needless writes.
  if (rec.exp - now < SESSION_TTL / 2) {
    rec.exp = now + SESSION_TTL;
    await kvPut(env, prefix + sid, JSON.stringify(rec), { expirationTtl: SESSION_TTL + 60 });
  }
  return sid;
}

async function dropSession(request, env, cookieName, prefix) {
  const sid = readCookie(request, cookieName);
  if (sid) await kvDel(env, prefix + sid);
}

/* ------------------------------------------------------------ rate limit */

async function lockUntil(env, ip) {
  const raw = await kvGet(env, `rl:${ip}`);
  if (!raw) return 0;
  try {
    const rec = JSON.parse(raw);
    return rec && rec.until > Math.floor(Date.now() / 1000) ? rec.until : 0;
  } catch {
    return 0;
  }
}

async function recordFailure(env, ip) {
  const key = `rl:${ip}`;
  let rec = { fails: 0, until: 0 };
  try {
    rec = JSON.parse((await kvGet(env, key)) || "null") || rec;
  } catch {
    /* start fresh */
  }
  rec.fails = (rec.fails || 0) + 1;
  if (rec.fails >= MAX_ATTEMPTS) {
    rec.until = Math.floor(Date.now() / 1000) + ATTEMPT_WINDOW;
    rec.fails = 0;
  }
  await kvPut(env, key, JSON.stringify(rec), { expirationTtl: ATTEMPT_WINDOW * 2 });
}

async function clearFailures(env, ip) {
  await kvDel(env, `rl:${ip}`);
}

async function refuse(env, request, message) {
  const ip = clientIp(request);
  const locked = await lockUntil(env, ip);
  if (locked) {
    const retry = locked - Math.floor(Date.now() / 1000);
    return json({ error: `Too many attempts. Retry in ${retry}s.` }, 429, {
      "Retry-After": String(Math.max(retry, 1)),
    });
  }
  await recordFailure(env, ip);
  return json({ error: message }, 401);
}

/* --------------------------------------------------------- step 1: gate */

function normText(v) {
  return String(v === undefined || v === null ? "" : v).trim().replace(/\s+/g, " ").toLowerCase();
}

function normDob(v) {
  const d = String(v === undefined || v === null ? "" : v).replace(/\D/g, "");
  if (d.length !== 8) return d;
  if (/^(19|20)\d{2}/.test(d)) return d; // YYYYMMDD
  return d.slice(4) + d.slice(2, 4) + d.slice(0, 2); // DDMMYYYY -> YYYYMMDD
}

function gateConfigured(env) {
  return Boolean(env.GATE_NAME && env.GATE_EMAIL && env.GATE_DOB && env.CONFIRMATION_ID);
}

async function gateMatches(env, body) {
  const expected = {
    name: normText(env.GATE_NAME),
    email: normText(env.GATE_EMAIL),
    dob: normDob(env.GATE_DOB),
    id: String(env.CONFIRMATION_ID).trim(),
  };
  const supplied = {
    name: normText(body.name),
    email: normText(body.email),
    dob: normDob(body.dob),
    id: String(body.confirmationId === undefined ? "" : body.confirmationId).trim(),
  };
  // Every field is always compared so the response time does not reveal
  // which one was wrong.
  const results = await Promise.all([
    safeEqual(supplied.name, expected.name),
    safeEqual(supplied.email, expected.email),
    safeEqual(supplied.dob, expected.dob),
    safeEqual(supplied.id, expected.id),
  ]);
  return results.every(Boolean);
}

async function handleGate(request, env) {
  if (!sameOrigin(request)) return json({ error: "Forbidden" }, 403);
  if (!gateConfigured(env)) return json({ error: "Gate not configured" }, 500);

  const ip = clientIp(request);
  const locked = await lockUntil(env, ip);
  if (locked) {
    const retry = locked - Math.floor(Date.now() / 1000);
    return json({ error: `Too many attempts. Retry in ${retry}s.` }, 429, {
      "Retry-After": String(Math.max(retry, 1)),
    });
  }

  let body;
  try {
    body = await readJson(request);
  } catch {
    return json({ error: "Invalid request" }, 400);
  }
  if (!body || typeof body !== "object") return json({ error: "Invalid request" }, 400);

  if (!(await gateMatches(env, body))) return refuse(env, request, "Details do not match.");

  await clearFailures(env, ip);
  const gid = await createSession(env, GATE_PREFIX);
  return json({ ok: true }, 200, {
    "Set-Cookie": sessionCookie(GATE_COOKIE, gid, SESSION_TTL),
  });
}

/* ------------------------------------------------------- step 2: unlock */

async function handleLogin(request, env) {
  if (!sameOrigin(request)) return json({ error: "Forbidden" }, 403);
  if (!env.AUTH_PASSWORD) return json({ error: "Server not configured" }, 500);

  const gate = await lookupSession(request, env, GATE_COOKIE, GATE_PREFIX);
  if (!gate) return json({ error: "gate_required" }, 403);

  const ip = clientIp(request);
  const locked = await lockUntil(env, ip);
  if (locked) {
    const retry = locked - Math.floor(Date.now() / 1000);
    return json({ error: `Too many attempts. Retry in ${retry}s.` }, 429, {
      "Retry-After": String(Math.max(retry, 1)),
    });
  }

  let body;
  try {
    body = await readJson(request);
  } catch {
    return json({ error: "Invalid request" }, 400);
  }

  const password = typeof body.password === "string" ? body.password : "";
  const ok = await safeEqual(password, env.AUTH_PASSWORD);

  if (!ok) return refuse(env, request, "Invalid password");

  await clearFailures(env, ip);
  const sid = await createSession(env, VAULT_PREFIX);
  return json({ ok: true }, 200, {
    "Set-Cookie": sessionCookie(VAULT_COOKIE, sid, SESSION_TTL),
  });
}

async function handleLogout(request, env) {
  if (!sameOrigin(request)) return json({ error: "Forbidden" }, 403);
  await dropSession(request, env, VAULT_COOKIE, VAULT_PREFIX);
  await dropSession(request, env, GATE_COOKIE, GATE_PREFIX);
  return json({ ok: true }, 200, {
    "Set-Cookie": [sessionCookie(VAULT_COOKIE, "", 0), sessionCookie(GATE_COOKIE, "", 0)],
    "Clear-Site-Data": '"cookies", "cache", "storage"',
  });
}

/* -------------------------------------------------------------- vault io */

/** Values supplied as Worker secrets: visible, never writable from the client. */
function secretEntries(env) {
  const out = [];
  const add = (id, label, kind, raw) => {
    const value = typeof raw === "string" ? raw.trim() : "";
    if (value) out.push({ id, label, kind, value, updatedAt: 0, readonly: true });
  };
  add("secret-bank-pin", "Bank debit card PIN", "pin", env.BANK_PIN);
  add("secret-pushtan", "pushTAN", "pushtan", env.PUSHTAN);
  return out;
}

function isUserEntry(item) {
  if (!item || typeof item !== "object") return true; // let validation reject it
  if (item.readonly === true) return false;
  if (typeof item.id === "string" && SECRET_ID.test(item.id)) return false;
  return true;
}

function validateEntries(input) {
  if (!Array.isArray(input)) throw new Error("bad payload");
  if (input.length > MAX_ENTRIES) throw new Error("too many entries");

  const out = [];
  const seen = new Set();
  for (const item of input) {
    if (!item || typeof item !== "object") throw new Error("bad entry");

    const label = typeof item.label === "string" ? item.label.trim().slice(0, MAX_LABEL) : "";
    if (!label) throw new Error("label required");

    const value = typeof item.value === "string" ? item.value : "";
    if (value.length > MAX_VALUE) throw new Error("value too long");

    const kind = KINDS.includes(item.kind) ? item.kind : "note";
    if (kind === "pin" && !/^\d{4,12}$/.test(value)) throw new Error("PIN must be 4-12 digits");
    if (kind === "pushtan" && value.length < 4) throw new Error("pushTAN value too short");

    let id =
      typeof item.id === "string" && ID_RE.test(item.id) ? item.id : randomToken(16);
    if (SECRET_ID.test(id)) id = randomToken(16);
    while (seen.has(id)) id = randomToken(16);
    seen.add(id);

    const updatedAt =
      Number.isFinite(item.updatedAt) && item.updatedAt > 0
        ? Math.floor(item.updatedAt)
        : Date.now();

    out.push({ id, label, kind, value, updatedAt });
  }
  return out;
}

async function loadVault(env) {
  const blob = await kvGet(env, "vault:data");
  if (!blob) return [];
  try {
    const data = await unseal(await vaultKey(env), blob);
    return Array.isArray(data) ? data : [];
  } catch {
    throw new Error("decrypt failed");
  }
}

async function saveVault(env, entries) {
  const sealed = await seal(await vaultKey(env), entries);
  await kvPut(env, "vault:data", sealed);
}

async function handleVault(request, env) {
  if (!sameOrigin(request)) return json({ error: "Forbidden" }, 403);

  const gate = await lookupSession(request, env, GATE_COOKIE, GATE_PREFIX);
  if (!gate) return json({ error: "gate_required" }, 403);

  const sid = await lookupSession(request, env, VAULT_COOKIE, VAULT_PREFIX);
  if (!sid) {
    return json({ error: "Unauthorized" }, 401, { "WWW-Authenticate": 'Bearer realm="vault"' });
  }

  if (request.method === "GET") {
    const entries = secretEntries(env).concat(await loadVault(env));
    return json({ entries });
  }

  let body;
  try {
    body = await readJson(request);
  } catch {
    return json({ error: "Invalid request" }, 400);
  }

  let entries;
  try {
    const raw = body && body.entries;
    entries = validateEntries(Array.isArray(raw) ? raw.filter(isUserEntry) : raw);
  } catch (err) {
    return json({ error: err.message === "bad payload" ? "Invalid request" : err.message }, 422);
  }

  await saveVault(env, entries);
  return json({ ok: true, count: entries.length });
}

/* ----------------------------------------------------------- static html */

function cspFor(nonce) {
  return [
    "default-src 'none'",
    `script-src 'nonce-${nonce}' 'strict-dynamic'`,
    `style-src 'nonce-${nonce}'`,
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
    "object-src 'none'",
    "media-src 'none'",
    "worker-src 'none'",
    "require-trusted-types-for 'script'",
    "trusted-types default",
    "upgrade-insecure-requests",
  ].join("; ");
}

async function serveUI(request, env) {
  if (request.method !== "GET" && request.method !== "HEAD") {
    return text("Method not allowed", 405, { Allow: "GET, HEAD" });
  }
  if (!env.ASSETS) return text("Assets binding missing", 500);

  const url = new URL(request.url);
  const assetPath = url.pathname === "/" ? "/index.html" : url.pathname;
  const asset = await env.ASSETS.fetch(new Request(new URL(assetPath, url), { method: "GET" }));

  const contentType = asset.headers.get("content-type") || "";

  if (!asset.ok || !contentType.includes("text/html")) {
    if (!asset.ok) return text("Not found", 404);
    const passthrough = { ...BASE_HEADERS, "Content-Type": contentType };
    const len = asset.headers.get("Content-Length");
    if (len) passthrough["Content-Length"] = len;
    return new Response(asset.body, { status: asset.status, headers: passthrough });
  }

  const nonce = randomToken(16);
  const html = (await asset.text()).split('nonce="dev"').join(`nonce="${nonce}"`);

  return new Response(html, {
    status: 200,
    headers: {
      ...BASE_HEADERS,
      "Content-Type": "text/html; charset=utf-8",
      "Content-Security-Policy": cspFor(nonce),
      "Cross-Origin-Embedder-Policy": "require-corp",
    },
  });
}

/* ---------------------------------------------------------------- router */

export default {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);
    try {
      if (pathname === "/api/gate" && request.method === "POST") {
        return await handleGate(request, env);
      }
      if (pathname === "/api/login" && request.method === "POST") {
        return await handleLogin(request, env);
      }
      if (pathname === "/api/logout" && request.method === "POST") {
        return await handleLogout(request, env);
      }
      if (pathname === "/api/vault") {
        if (request.method !== "GET" && request.method !== "PUT") {
          return json({ error: "Method not allowed" }, 405, { Allow: "GET, PUT" });
        }
        return await handleVault(request, env);
      }
      if (pathname.startsWith("/api/")) {
        return json({ error: "Not found" }, 404);
      }
      return await serveUI(request, env);
    } catch {
      // Never echo internals - error text can leak configuration details.
      return json({ error: "Server error" }, 500);
    }
  },
};
