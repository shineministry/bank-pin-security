/* Integration tests for worker.js - run with: node test/vault.test.mjs */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const html = fs.readFileSync(path.join(root, "public", "index.html"), "utf8");

/* ------------------------- Workers runtime shims ------------------------- */

const store = new Map();
const stub = {
  async kvGet(k) { return store.has(k) ? store.get(k) : null; },
  async kvPut(k, v) { store.set(k, v); },
  async kvDelete(k) { store.delete(k); },
};
const VAULT = { idFromName: () => "main", get: () => stub };

const ASSETS = {
  async fetch(req) {
    const p = new URL(req.url).pathname;
    if (p === "/" || p === "/index.html") {
      return new Response(html, { status: 200, headers: { "content-type": "text/html; charset=utf-8" } });
    }
    return new Response("nf", { status: 404, headers: { "content-type": "text/plain" } });
  },
};

const env = {
  VAULT,
  ASSETS,
  AUTH_PASSWORD: "correct-horse-battery",
  VAULT_KEY: "unit-test-key-0123456789",
  BANK_PIN: "4821",
  PUSHTAN: "AB12CD34",
  GATE_NAME: "Shineil Mathias",
  GATE_EMAIL: "Shineil@Example.com",
  GATE_DOB: "1998-04-17",
  CONFIRMATION_ID: "CNF-77341",
};

const { default: worker } = await import(pathToFileURL(path.join(root, "worker.js")).href);

/* --------------------------------- harness -------------------------------- */

let fails = 0;
const check = (name, cond, extra = "") => {
  if (cond) console.log("PASS " + name);
  else { fails++; console.log("FAIL " + name + (extra ? " :: " + extra : "")); }
};

const base = "https://security2.shinumaths989.workers.dev";
const cookies = Object.create(null);

function jar(res) {
  const all = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
  for (const c of all) {
    const pair = c.split(";")[0];
    const i = pair.indexOf("=");
    const name = pair.slice(0, i).trim();
    const value = pair.slice(i + 1);
    if (value) cookies[name] = value; else delete cookies[name];
  }
}
const cookieHeader = () =>
  Object.entries(cookies).map(([k, v]) => k + "=" + v).join("; ");

async function req(pathname, opt = {}, ip) {
  const headers = new Headers(opt.headers || {});
  if (ip) headers.set("cf-connecting-ip", ip);
  if (Object.keys(cookies).length) headers.set("Cookie", cookieHeader());
  const res = await worker.fetch(new Request(base + pathname, { ...opt, headers }), env);
  jar(res);
  return res;
}
const post = (p, body, ip) =>
  req(p, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) }, ip);
const put = (p, body, ip) =>
  req(p, { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify(body) }, ip);

const GATE_OK = { name: "  shineil   mathias ", email: "shineil@example.com", dob: "17-04-1998", confirmationId: "CNF-77341" };

/* --------------------------------- 1. UI ---------------------------------- */

let res = await req("/");
let body = await res.text();
const csp = res.headers.get("content-security-policy") || "";
check("UI 200", res.status === 200);
check("UI nonce CSP", /script-src 'nonce-[A-Za-z0-9_-]+' 'strict-dynamic'/.test(csp), csp);
check("no dev nonce left", !body.includes('nonce="dev"'));
check("script tag got nonce", /<script nonce="[A-Za-z0-9_-]{10,}">/.test(body));
check("style tag got nonce", /<style nonce="[A-Za-z0-9_-]{10,}">/.test(body));
check("trusted-types on", csp.includes("require-trusted-types-for 'script'"));
check("HSTS", (res.headers.get("strict-transport-security") || "").includes("max-age=31536000"));
check("no-store", (res.headers.get("cache-control") || "").includes("no-store"));
check("nosniff", res.headers.get("x-content-type-options") === "nosniff");
check("frame deny", res.headers.get("x-frame-options") === "DENY");
check("no referrer", res.headers.get("referrer-policy") === "no-referrer");
check("no index", (res.headers.get("x-robots-tag") || "").includes("noindex"));
check("gate form present", body.includes('id="gateForm"'));
check("4 gate fields present",
  ["gName", "gEmail", "gDob", "gId"].every(id => body.includes('id="' + id + '"')));
check("pass pane present", body.includes('id="passPane"'));

/* ------------------------- 2. gate must come first ------------------------ */

res = await req("/api/vault");
check("vault blocked before gate", res.status === 403 && (await res.json()).error === "gate_required");

res = await post("/api/login", { password: "correct-horse-battery" }, "10.0.0.10");
check("login blocked before gate", res.status === 403);

/* ------------------------- 3. gate rate limiting -------------------------- */

for (let i = 0; i < 5; i++) {
  res = await post("/api/gate", { ...GATE_OK, confirmationId: "WRONG-" + i }, "10.0.0.1");
}
check("gate attempts 1-5 -> 401", res.status === 401, "got " + res.status);
res = await post("/api/gate", GATE_OK, "10.0.0.1");
check("gate 6th -> 429", res.status === 429, "got " + res.status);
check("lockout Retry-After", !!res.headers.get("retry-after"));

/* ---------------------- 4. gate accepts normalisation --------------------- */

res = await post("/api/gate", GATE_OK, "10.0.0.2");
check("gate 200 (whitespace/case/dob order normalised)", res.status === 200, "got " + res.status);
check("gate cookie HttpOnly", (res.headers.get("set-cookie") || "").includes("HttpOnly"));
check("gate cookie __Host-", (res.headers.get("set-cookie") || "").startsWith("__Host-gate_sid="));
check("gate cookie Secure", (res.headers.get("set-cookie") || "").includes("Secure"));
check("gate cookie SameSite=Strict", (res.headers.get("set-cookie") || "").includes("SameSite=Strict"));

res = await req("/api/vault", {}, "10.0.0.2");
check("vault still 401 after gate (no password yet)", res.status === 401, "got " + res.status);

/* -------------------------- 5. login rate limiting ------------------------ */

for (let i = 0; i < 5; i++) res = await post("/api/login", { password: "nope" + i }, "10.0.0.3");
check("login attempts 1-5 -> 401", res.status === 401, "got " + res.status);
res = await post("/api/login", { password: "correct-horse-battery" }, "10.0.0.3");
check("login 6th -> 429", res.status === 429, "got " + res.status);

/* ------------------------------ 6. full unlock ---------------------------- */

res = await post("/api/login", { password: "correct-horse-battery" }, "10.0.0.4");
check("login 200", res.status === 200, "got " + res.status);
check("vault cookie __Host-vault_sid", (res.headers.get("set-cookie") || "").startsWith("__Host-vault_sid="));

res = await req("/api/vault", {}, "10.0.0.4");
let data = await res.json();
check("vault reachable", res.status === 200, JSON.stringify(data));
check("bank PIN served from secret", data.entries.some(e => e.id === "secret-bank-pin" && e.value === "4821" && e.readonly === true));
check("pushTAN served from secret", data.entries.some(e => e.id === "secret-pushtan" && e.value === "AB12CD34" && e.readonly === true));
check("secret ids cannot be guessed into KV", data.entries.every(e => !e.id.startsWith("secret-") || e.readonly === true));

/* ------------------- 7. client cannot overwrite secrets ------------------- */

res = await put("/api/vault", {
  entries: [
    { id: "secret-bank-pin", label: "hijack", kind: "pin", value: "9999", readonly: true },
    { id: "secret-pushtan", label: "hijack", kind: "pushtan", value: "ZZZZZZZZ" },
    { label: "Savings ATM", kind: "pin", value: "5678" },
  ],
}, "10.0.0.4");
check("put accepted", res.status === 200, JSON.stringify(await res.json()));

res = await req("/api/vault", {}, "10.0.0.4");
data = await res.json();
check("secret PIN not overwritten", data.entries.find(e => e.id === "secret-bank-pin").value === "4821");
check("secret pushTAN not overwritten", data.entries.find(e => e.id === "secret-pushtan").value === "AB12CD34");
check("secret labels untouched", data.entries.find(e => e.id === "secret-bank-pin").label === "Bank debit card PIN");
check("user entry stored", data.entries.some(e => e.label === "Savings ATM" && e.value === "5678"));
check("exactly 3 entries", data.entries.length === 3, "len=" + data.entries.length);

/* --------------------------- 8. encryption at rest ------------------------ */

const blob = await store.get("vault:data");
check("at rest is not plaintext", blob && !blob.includes("5678") && !blob.includes("Savings"), String(blob).slice(0, 40));
check("at rest is base64", /^[A-Za-z0-9+/=]+$/.test(blob || ""));

/* ------------------------------ 9. validation ----------------------------- */

const bad = [
  ["short pin", [{ label: "x", kind: "pin", value: "12" }]],
  ["empty label", [{ label: "", kind: "note", value: "v" }]],
  ["non-array", "nope"],
  ["too many", Array.from({ length: 201 }, (_, i) => ({ label: "x" + i, kind: "note", value: "v" }))],
  ["long value", [{ label: "a".repeat(64), kind: "note", value: "v".repeat(300) }]],
  ["short pushtan", [{ label: "x", kind: "pushtan", value: "ab" }]],
];
for (const [name, entries] of bad) {
  res = await put("/api/vault", { entries }, "10.0.0.4");
  check("reject " + name, res.status === 422, "got " + res.status);
}

res = await req("/api/vault", {}, "10.0.0.4");
data = await res.json();
check("vault unchanged after rejects", data.entries.length === 3, "len=" + data.entries.length);

/* ---------------------------- 10. transport rules ------------------------- */

res = await req("/api/vault", { headers: { "sec-fetch-site": "cross-site" } }, "10.0.0.4");
check("cross-site 403", res.status === 403, "got " + res.status);
res = await req("/api/vault", { headers: { origin: "https://evil.example" } }, "10.0.0.4");
check("foreign origin 403", res.status === 403, "got " + res.status);
res = await req("/api/vault", { method: "DELETE" }, "10.0.0.4");
check("405 on DELETE", res.status === 405, "got " + res.status);
res = await req("/api/nope");
check("404 on unknown api", res.status === 404, "got " + res.status);
res = await req("/favicon.ico");
check("asset 404", res.status === 404, "got " + res.status);
res = await req("/", { method: "POST" });
check("POST / 405", res.status === 405, "got " + res.status);

/* ----------------------------- 11. misconfig ------------------------------ */

const bare = { ...env, GATE_DOB: undefined };
res = await worker.fetch(new Request(base + "/api/gate", {
  method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(GATE_OK),
}), bare);
check("gate fails closed when unconfigured", res.status === 500, "got " + res.status);

/* ------------------------------- 12. logout ------------------------------- */

res = await post("/api/logout", {}, "10.0.0.4");
check("logout 200", res.status === 200, "got " + res.status);
const setCookies = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
check("logout clears both cookies", setCookies.filter(c => c.includes("Max-Age=0")).length === 2, JSON.stringify(setCookies));
check("Clear-Site-Data", (res.headers.get("clear-site-data") || "").includes("cookies"));
res = await req("/api/vault", {}, "10.0.0.4");
check("session dead after logout", res.status === 403, "got " + res.status);

console.log(fails === 0 ? "\nALL TESTS PASSED" : `\n${fails} FAILED`);
process.exit(fails ? 1 : 0);
