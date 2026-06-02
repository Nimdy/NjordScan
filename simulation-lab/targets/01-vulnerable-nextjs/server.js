"use strict";

// Minimal self-contained server that mirrors the vulnerable surface of the
// ShopDash app for dynamic (DAST) scanning, without needing a Next.js build.
// Same bugs, fewer moving parts. Listens on PORT (default 3001).

const http = require("http");
const { URL } = require("url");
const { exec } = require("child_process");
const fs = require("fs");
const pathmod = require("path");

const PORT = parseInt(process.env.PORT || "3001", 10);

// Purple-team access log: one JSON line per request to <LOG_DIR>/web.log — the
// LOG CONTRACT the blue-team detector consumes. Best-effort; never affects responses.
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

// Hard-coded creds, same as the .env the real app reads.
const STRIPE_SECRET_KEY = "lab_demo_key_a3f9c2b18d7e6f5a4b3c2d1e0f9a8b7c";

function send(res, status, body, headers) {
  // Note: no X-Frame-Options, no Content-Security-Policy, no
  // Strict-Transport-Security — set on purpose so the scanner sees them missing.
  const base = {
    "Content-Type": "text/html; charset=utf-8",
    "X-Powered-By": "ShopDash",
  };
  res.writeHead(status, Object.assign(base, headers || {}));
  res.end(body);
}

const server = http.createServer((req, res) => {
  const u = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  logAccess(req, res, u, "web");

  // --- reflected XSS: the query is echoed straight into the HTML ----------
  if (u.pathname === "/search") {
    const q = u.searchParams.get("q") || "";
    const html =
      "<!doctype html><html><body>" +
      "<h1>Search results</h1>" +
      "<p>You searched for: " + q + "</p>" +
      "</body></html>";
    return send(res, 200, html);
  }

  // --- open redirect: redirect target taken from the query string ---------
  if (u.pathname === "/go") {
    const target = u.searchParams.get("url") || "/";
    return send(res, 302, "Redirecting...", { Location: target });
  }

  // --- insecure session cookie: no HttpOnly, no Secure, no SameSite -------
  if (u.pathname === "/login") {
    const token = "eyJhbGciOiJIUzI1NiJ9.demo.signature";
    return send(res, 200, "<p>Logged in.</p>", {
      "Set-Cookie": "session=" + token + "; Path=/",
    });
  }

  // --- command injection: host param flows into a shell command ----------
  if (u.pathname === "/ping") {
    const host = u.searchParams.get("host") || "localhost";
    exec("ping -c 1 " + host, (err, stdout) => {
      if (err) {
        return send(res, 200, "<pre>ping failed</pre>");
      }
      send(res, 200, "<pre>" + stdout + "</pre>");
    });
    return;
  }

  // --- verbose 500: leaks the stack trace (and a secret) to the client ---
  if (u.pathname === "/boom") {
    try {
      throw new Error("Database connection failed for " + STRIPE_SECRET_KEY);
    } catch (err) {
      return send(
        res,
        500,
        "<h1>500 Internal Server Error</h1><pre>" + err.stack + "</pre>"
      );
    }
  }

  if (u.pathname === "/") {
    return send(
      res,
      200,
      "<h1>ShopDash</h1><p>Try /search?q=, /go?url=, /ping?host=, /boom</p>"
    );
  }

  return send(res, 404, "<h1>404 Not Found</h1>");
});

server.listen(PORT, () => {
  console.log("ShopDash demo server listening on http://0.0.0.0:" + PORT);
});
