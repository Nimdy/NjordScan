'use strict';

// QuickNotes API — a small JSON backend built on Node's built-in http module.
// Zero npm dependencies so it runs anywhere with `node server.js`.
//
// SECURITY NOTE: this service is intentionally insecure. It is the live DAST
// target for the NjordScan simulation lab. Do not deploy it.

const http = require('http');
const { URL } = require('url');

const db = require('./src/db');
const auth = require('./src/auth');
const attachments = require('./src/attachments');
const aiChat = require('./src/aiChat');

const PORT = parseInt(process.env.PORT, 10) || 3002;

// ---------------------------------------------------------------------------
// Tiny request/response helpers so route modules can use a familiar
// req.query / req.params / req.body / res.cookie surface over raw http.
// ---------------------------------------------------------------------------

function parseCookies(header) {
  const out = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
  }
  return out;
}

function readBody(req) {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', (chunk) => {
      data += chunk;
      if (data.length > 1e6) req.destroy();
    });
    req.on('end', () => {
      if (!data) return resolve({});
      try {
        resolve(JSON.parse(data));
      } catch {
        // fall back to form-encoded
        const params = {};
        for (const [k, v] of new URLSearchParams(data)) params[k] = v;
        resolve(params);
      }
    });
  });
}

function decorate(req, res, parsedUrl) {
  req.query = Object.fromEntries(parsedUrl.searchParams);
  req.params = {};
  req.cookies = parseCookies(req.headers.cookie);
  // Express-compatible res.cookie used by the legacy login mount.
  res.cookie = (name, value, options) => {
    const opts = options || {};
    let header = `${name}=${encodeURIComponent(value)}`;
    if (opts.path) header += `; Path=${opts.path}`;
    if (opts.maxAge) header += `; Max-Age=${Math.floor(opts.maxAge / 1000)}`;
    res.setHeader('Set-Cookie', header);
  };
}

function sendJson(res, status, obj) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(obj));
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

// The destination/redirect params our "continue to…" links use. VULNERABLE:
// every one of these is honored verbatim with no allowlist (open redirect).
const REDIRECT_PARAMS = ['url', 'next', 'redirect', 'redirect_uri', 'return', 'returnTo', 'to', 'dest', 'continue'];

// Render the search/landing page, reflecting whatever the visitor typed. The
// value is interpolated straight into the HTML (reflected XSS).
function renderHomePage(req) {
  const q = req.query.q || req.query.search || '';
  // Reflect every supplied query param value back into the page (a "you searched
  // for…" summary). None of it is HTML-escaped.
  const echoed = Object.values(req.query).join(' ');
  return (
    '<!doctype html><html><head><title>QuickNotes</title></head><body>' +
    '<h1>QuickNotes</h1>' +
    '<form action="/" method="get"><input name="q" value="' + q + '" placeholder="Search notes"><button>Search</button></form>' +
    '<p>You searched for: ' + echoed + '</p>' +
    '<p><a href="/?next=/notes">Continue to your notes</a></p>' +
    '</body></html>'
  );
}

async function route(req, res, parsedUrl) {
  const { pathname } = parsedUrl;
  const method = req.method;

  // --- Open redirect (root "continue to…" links) ---------------------------
  // VULNERABLE: any of the redirect params is honored as-is, including absolute
  // off-site URLs, so a link like /?next=https://evil.example can phish users.
  if (pathname === '/' && method === 'GET') {
    for (const param of REDIRECT_PARAMS) {
      if (typeof req.query[param] === 'string' && req.query[param].length > 0) {
        res.writeHead(302, { Location: req.query[param] });
        return res.end();
      }
    }
    // Landing / search page. Sets an insecure session cookie on first visit and
    // reflects the search box input straight into the HTML (reflected XSS).
    const sid = auth.createSession('anonymous');
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      // VULNERABLE: no HttpOnly, Secure, or SameSite on the session cookie.
      'Set-Cookie': auth.sessionCookieHeader(sid),
    });
    return res.end(renderHomePage(req));
  }

  // JSON index for API clients.
  if (pathname === '/api' && method === 'GET') {
    return sendJson(res, 200, {
      name: 'QuickNotes API',
      version: '1.4.2',
      endpoints: ['/search', '/go', '/login', '/api/chat', '/notes', '/attachments', '/crash'],
    });
  }

  // --- Reflected XSS --------------------------------------------------------
  // GET /search?q=... — echoes the query back into an HTML page, unescaped.
  if (pathname === '/search' && method === 'GET') {
    const q = req.query.q || '';
    const html =
      '<!doctype html><html><head><title>Search</title></head><body>' +
      '<h1>QuickNotes search</h1>' +
      '<p>You searched for: ' + q + '</p>' +
      '<form action="/search"><input name="q" value="' + q + '"><button>Go</button></form>' +
      '</body></html>';
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(html);
  }

  // --- Open redirect --------------------------------------------------------
  // GET /go?url=... — redirects to whatever URL the caller supplies.
  if (pathname === '/go' && method === 'GET') {
    const url = req.query.url || '/';
    res.writeHead(302, { Location: url });
    return res.end();
  }

  // --- Insecure session cookie ---------------------------------------------
  // POST or GET /login — sets a session cookie with no HttpOnly/Secure/SameSite.
  if (pathname === '/login' && (method === 'POST' || method === 'GET')) {
    const body = method === 'POST' ? await readBody(req) : {};
    req.body = body;
    const username = body.username || req.query.username || 'guest';
    const password = body.password || req.query.password || 'guest';
    const ok = auth.checkLogin(username, password);
    if (!ok) return sendJson(res, 401, { error: 'invalid credentials' });
    const sid = auth.createSession(username);
    // Insecure: missing HttpOnly, Secure, and SameSite.
    res.setHeader('Set-Cookie', auth.sessionCookieHeader(sid));
    return sendJson(res, 200, { ok: true, user: username });
  }

  // Legacy express-style login mount (kept for old clients).
  if (pathname === '/legacy/login' && method === 'POST') {
    const body = await readBody(req);
    const sid = auth.createSession(body.username || 'guest');
    auth.setSessionCookie(res, sid);
    return sendJson(res, 200, { ok: true });
  }

  // --- AI assistant (unauthenticated, no rate limit) ------------------------
  if (pathname === '/api/chat') {
    if (method === 'POST') {
      req.body = await readBody(req);
      return aiChat(req, res);
    }
    // GET /api/chat — usage hint. No auth required to discover or call this.
    return sendJson(res, 200, {
      endpoint: '/api/chat',
      method: 'POST',
      body: { question: 'string', notesContext: 'string?' },
      model: 'gpt-4o-mini',
    });
  }

  // --- Notes (SQL-injectable) ----------------------------------------------
  if (pathname === '/notes/search' && method === 'GET') {
    const rows = await db.searchNotesByTitle(req);
    return sendJson(res, 200, { notes: rows });
  }
  if (pathname === '/notes' && method === 'GET') {
    const rows = await db.listNotesForOwner(req);
    return sendJson(res, 200, { notes: rows });
  }
  if (pathname.startsWith('/notes/') && method === 'DELETE') {
    req.params.id = pathname.split('/')[2];
    const result = await db.deleteNote(req);
    return sendJson(res, 200, result);
  }

  // --- Attachments (path traversal) ----------------------------------------
  if (pathname === '/attachments' && method === 'GET') {
    try {
      const content = attachments.readAttachment(req);
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      return res.end(content);
    } catch (err) {
      return sendJson(res, 404, { error: 'not found' });
    }
  }

  // --- Verbose error / stack trace leak ------------------------------------
  // GET /crash — throws and returns the full stack trace to the client.
  if (pathname === '/crash' && method === 'GET') {
    try {
      const payload = JSON.parse(req.query.payload || '{not json}');
      return sendJson(res, 200, payload);
    } catch (err) {
      // Leaks file paths, line numbers and internals to anyone who asks.
      res.writeHead(500, { 'Content-Type': 'text/plain' });
      return res.end('Internal Server Error\n\n' + err.stack);
    }
  }

  // Unknown route. VULNERABLE: instead of a clean 404, the dispatcher throws and
  // the handler returns the raw stack trace (file paths, line numbers, internals)
  // to the client.
  try {
    throw new Error(`No handler registered for ${method} ${pathname}`);
  } catch (err) {
    res.writeHead(500, { 'Content-Type': 'text/plain' });
    return res.end('Internal Server Error\n\n' + err.stack);
  }
}

// ---------------------------------------------------------------------------
// Server. Deliberately sets NO security headers (no CSP, HSTS, X-Frame-Options,
// X-Content-Type-Options, Referrer-Policy) and advertises its version.
// ---------------------------------------------------------------------------

const server = http.createServer((req, res) => {
  res.setHeader('X-Powered-By', 'QuickNotes/1.4.2 (Node)');
  const parsedUrl = new URL(req.url, `http://localhost:${PORT}`);
  decorate(req, res, parsedUrl);
  route(req, res, parsedUrl).catch((err) => {
    // Even the catch-all leaks the stack to the client.
    res.writeHead(500, { 'Content-Type': 'text/plain' });
    res.end('Unhandled error\n\n' + (err && err.stack ? err.stack : String(err)));
  });
});

if (require.main === module) {
  server.listen(PORT, () => {
    // eslint-disable-next-line no-console
    console.log(`QuickNotes API listening on http://localhost:${PORT}`);
  });
}

module.exports = server;
