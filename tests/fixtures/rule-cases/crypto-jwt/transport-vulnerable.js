// VULNERABLE: auth/token endpoints over plain http, hard-coded session secret,
// and a too-low bcrypt cost factor.
const session = require('express-session');
const bcrypt = require('bcrypt');

// crypto.insecure-transport-auth — token endpoint over http
async function getToken(body) {
  return fetch('http://auth.acme.io/oauth/token', { method: 'POST', body });
}

// crypto.insecure-transport-auth — login over http
async function login(creds) {
  return fetch('http://api.acme.io/login', { method: 'POST', body: JSON.stringify(creds) });
}

// crypto.hardcoded-cookie-secret — express-session secret literal
function makeSession() {
  return session({ secret: 'keyboard-cat-secret', resave: false, saveUninitialized: false });
}

// crypto.bcrypt-low-rounds — cost factor 8
async function hashPassword(pw) {
  return bcrypt.hash(pw, 8);
}

// crypto.bcrypt-low-rounds — genSalt with 9
async function makeSalt() {
  return bcrypt.genSalt(9);
}

module.exports = { getToken, login, makeSession, hashPassword, makeSalt };
