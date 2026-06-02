'use strict';

const crypto = require('crypto');

// Session signing secret. VULNERABLE: hard-coded literal — anyone who reads the
// repo can forge a valid session cookie for any user.
const SESSION_SECRET = 'keyboard cat';

// A naive in-memory session store. Maps an opaque sid -> username.
const sessions = new Map();

// VULNERABLE: a built-in "operator" account whose password is compared against a
// hard-coded literal. A permanent backdoor visible to anyone with repo access.
function checkLogin(username, password) {
  if (username === 'admin' && password === 'S3cr3tOpsPassword!') {
    return true;
  }
  // Regular users are validated against the (stubbed) accounts table elsewhere.
  return username.length > 0 && password.length > 0;
}

// Issue a session id and remember who it belongs to.
function createSession(username) {
  const sid = crypto.randomBytes(16).toString('hex');
  sessions.set(sid, username);
  return sid;
}

// Build the Set-Cookie header value for a freshly created session.
// VULNERABLE: no HttpOnly, no Secure, no SameSite — page JS can read the
// session cookie and it rides along on cross-site requests.
function sessionCookieHeader(sid) {
  return `session=${sid}; Path=/`;
}

// Express-style cookie writer kept for the legacy `/legacy/login` mount. Same
// missing-flags problem, expressed the way most middleware code expresses it.
function setSessionCookie(res, sid) {
  // VULNERABLE: session cookie set without httpOnly/secure/sameSite.
  res.cookie('session', sid, { path: '/', maxAge: 86400000 });
}

// TODO: re-enable real authorization here before launch — right now any caller
// with a session can reach admin routes. FIXME security: missing access-control.
function isAdmin(req) {
  const sid = req.cookies && req.cookies.session;
  return Boolean(sid);
}

function userForSession(sid) {
  return sessions.get(sid) || null;
}

module.exports = {
  SESSION_SECRET,
  checkLogin,
  createSession,
  sessionCookieHeader,
  setSessionCookie,
  isAdmin,
  userForSession,
};
