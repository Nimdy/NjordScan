"use strict";

// ── Target 06: the SEGMENTED internal admin tier ("BackOffice") ──────────────
//
// This service holds the crown jewels — the customer datastore (synthetic PII).
// It lives on its OWN network (compose's `internal-net`, marked `internal: true`)
// and is NOT published to the host. Crucially it is NOT on `labnet`, so the
// red-team container has no route to it. The only thing that can reach it is the
// DMZ web tier, which sits on both networks.
//
// It is reached in the lab exactly two ways:
//   • legitimately — the web app proxies its /account page to /account here, and
//   • maliciously — an attacker who lands RCE on the web tier pivots in and hits
//     /admin/customers to bulk-exfiltrate PII.
//
// That asymmetry is the whole point: /account is benign traffic the blue team
// stays silent on; ANY hit on /admin/* is a DMZ→internal pivot landing on the
// datastore. Same dependency-free style as the other targets. Listens on PORT
// (default 9000).

const http = require("http");
const { URL } = require("url");
const fs = require("fs");
const pathmod = require("path");

const PORT = parseInt(process.env.PORT || "9000", 10);

// Hard-coded internal credentials — the anti-pattern NjordScan flags on a static
// scan of this target (a DB password and the shared service token).
const INTERNAL_DB_PASSWORD = "Pg!backoffice_prod_9f3c2a7b1e";
const INTERNAL_API_TOKEN =
  process.env.INTERNAL_API_TOKEN || "sk_internal_adm_7c4e9f2a1b8d6e3f0a5c9b2d4e6f8a1c";

// The crown jewels: the customer datastore (entirely synthetic PII).
const CUSTOMERS = [
  { id: 1, name: "Alice Tan", email: "alice@example.com", ssn: "511-23-8842", card: "4242 4242 4242 4242" },
  { id: 2, name: "Marcus Reed", email: "marcus@example.com", ssn: "402-88-1190", card: "5500 0000 0000 0004" },
  { id: 3, name: "Priya Nair", email: "priya@example.com", ssn: "623-45-0917", card: "3782 822463 10005" },
];

// Purple-team access log — the same LOG CONTRACT the other targets write, with
// svc="internal", so the blue team's mini-SIEM picks it up automatically.
const LOG_DIR = process.env.LOG_DIR || "/logs";
try { fs.mkdirSync(LOG_DIR, { recursive: true }); } catch (e) { /* not writable -> no logs */ }
function _safeDecode(s) { try { return decodeURIComponent(s); } catch (e) { return s; } }
function logAccess(req, res, u, svc) {
  res.on("finish", () => {
    try {
      fs.appendFile(pathmod.join(LOG_DIR, svc + ".log"), JSON.stringify({
        ts: new Date().toISOString(), svc,
        ip: String(req.headers["x-forwarded-for"] || (req.socket && req.socket.remoteAddress) || ""),
        method: req.method, path: u.pathname, query: _safeDecode(u.search.replace(/^\?/, "")),
        status: res.statusCode, ua: req.headers["user-agent"] || "",
        ref: req.headers["referer"] || "", body: "",
      }) + "\n", () => {});
    } catch (e) { /* never break the request */ }
  });
}

function json(res, status, obj) {
  res.writeHead(status, { "Content-Type": "application/json", "X-Powered-By": "BackOffice" });
  res.end(JSON.stringify(obj));
}

// The shared service token is accepted via the X-Internal-Token header OR a
// ?token= query param, so a busybox-wget pivot (no easy header support) can still
// authenticate once it has looted the token from the web tier.
function tokenOf(req, u) {
  return req.headers["x-internal-token"] || u.searchParams.get("token") || "";
}

const server = http.createServer((req, res) => {
  const u = new URL(req.url, `http://${req.headers.host || "internal"}`);
  logAccess(req, res, u, "internal");

  if (u.pathname === "/") {
    return json(res, 200, { service: "BackOffice (internal)", note: "not for external exposure" });
  }

  // Per-user lookup the web tier legitimately proxies. This is BENIGN traffic —
  // the blue team must stay silent on it (precision control for the pivot demo).
  if (u.pathname === "/account") {
    if (tokenOf(req, u) !== INTERNAL_API_TOKEN) return json(res, 401, { error: "unauthorized" });
    const id = parseInt(u.searchParams.get("id") || "1", 10);
    const c = CUSTOMERS.find((x) => x.id === id);
    return json(res, 200, c ? { id: c.id, name: c.name, email: c.email } : { error: "not found" });
  }

  // The crown jewels: the full customer datastore. The application NEVER calls
  // this endpoint — only a pivoting attacker does. Any hit here is the pivot
  // landing on the PII store.
  if (u.pathname === "/admin/customers") {
    if (tokenOf(req, u) !== INTERNAL_API_TOKEN) return json(res, 401, { error: "unauthorized" });
    return json(res, 200, { count: CUSTOMERS.length, customers: CUSTOMERS });
  }

  // The DB-admin status endpoint embeds the datastore password in its reply (an
  // extra secret to loot once you're inside — and a static-scan finding).
  if (u.pathname === "/admin/db-status") {
    if (tokenOf(req, u) !== INTERNAL_API_TOKEN) return json(res, 401, { error: "unauthorized" });
    return json(res, 200, { engine: "postgres", connected: true, dsn: "postgres://backoffice:" + INTERNAL_DB_PASSWORD + "@db:5432/prod" });
  }

  return json(res, 404, { error: "not found" });
});

server.listen(PORT, () => {
  console.log("BackOffice internal service listening on http://0.0.0.0:" + PORT);
});
