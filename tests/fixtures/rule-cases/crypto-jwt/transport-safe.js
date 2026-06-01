// SAFE: https auth endpoints, session secret from env, strong bcrypt cost.
const session = require('express-session');
const bcrypt = require('bcrypt');

// https -> insecure-transport-auth must NOT fire
async function getToken(body) {
  return fetch('https://auth.acme.io/oauth/token', { method: 'POST', body });
}

// http to a non-auth path (assets) -> must NOT fire (no auth keyword)
async function getLogo() {
  return fetch('http://cdn.acme.io/static/logo.png');
}

// localhost dev login over http -> excluded, must NOT fire
async function devLogin(creds) {
  return fetch('http://localhost:3000/login', { method: 'POST', body: JSON.stringify(creds) });
}

// session secret from env -> hardcoded-cookie-secret must NOT fire
function makeSession() {
  return session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false });
}

// bcrypt cost 12 -> bcrypt-low-rounds must NOT fire
async function hashPassword(pw) {
  return bcrypt.hash(pw, 12);
}

module.exports = { getToken, getLogo, devLogin, makeSession, hashPassword };
