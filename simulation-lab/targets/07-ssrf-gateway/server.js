"use strict";

// ── Target 07: SSRF gateway ("LinkPreview") ──────────────────────────────────
//
// A URL-preview / image-proxy microservice — the kind every app eventually adds.
// It fetches a USER-SUPPLIED url server-side with no host validation, so it's a
// textbook SSRF. And because this service is on BOTH networks (labnet + internal-net),
// the SSRF is a *second path to the crown jewels*: an attacker can make it fetch
// http://internal:9000/admin/customers and read the customer datastore — no RCE, no
// pivot box, just one unvalidated fetch.
//
// NjordScan flags the SSRF statically (ssrf.fetch on a dynamic/attacker-controlled
// host — exactly the case the same-origin fix keeps precise). Listens on PORT (3003).

const http = require("http");
const { URL } = require("url");
const fs = require("fs");
const pathmod = require("path");

const PORT = parseInt(process.env.PORT || "3003", 10);

// Hard-coded internal token (the anti-pattern NjordScan flags on a static scan).
const INTERNAL_API_TOKEN = "sk_internal_adm_7c4e9f2a1b8d6e3f0a5c9b2d4e6f8a1c";

const LOG_DIR = process.env.LOG_DIR || "/logs";
try { fs.mkdirSync(LOG_DIR, { recursive: true }); } catch (e) { /* not writable */ }
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

function send(res, status, body, headers) {
  res.writeHead(status, Object.assign({ "Content-Type": "text/html; charset=utf-8", "X-Powered-By": "LinkPreview" }, headers || {}));
  res.end(body);
}

const server = http.createServer((req, res) => {
  const u = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  logAccess(req, res, u, "ssrf");

  // --- SSRF: fetch a user-controlled URL server-side, no allow-list ----------
  if (u.pathname === "/fetch" || u.pathname === "/preview" || u.pathname === "/og") {
    const target = u.searchParams.get("url") || u.searchParams.get("target");
    if (!target) return send(res, 400, "<p>pass ?url=</p>");
    // VULNERABLE: the host is attacker-controlled and never validated.
    fetch(target)
      .then((r) => r.text())
      .then((text) => send(res, 200, "<pre>" + text.slice(0, 4000) + "</pre>"))
      .catch((err) => send(res, 502, "<pre>fetch failed: " + err.message + "</pre>"));
    return;
  }

  // --- a SAFE, same-origin call (NjordScan must NOT flag this as SSRF) --------
  if (u.pathname === "/health/api") {
    fetch(`/api/internal-status`).then(() => send(res, 200, "ok")).catch(() => send(res, 200, "ok"));
    return;
  }

  if (u.pathname === "/") {
    return send(res, 200,
      "<h1>LinkPreview</h1><p>Try /fetch?url=https://example.com (server-side fetch — no host allow-list).</p>");
  }
  return send(res, 404, "<h1>404</h1>");
});

server.listen(PORT, () => console.log("LinkPreview SSRF gateway on http://0.0.0.0:" + PORT));
