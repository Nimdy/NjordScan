// VULNERABLE: JWT misuse. Each line below should fire exactly one crypto-jwt rule.
const jwt = require('jsonwebtoken');

// jwt.hardcoded-secret — secret is a literal string
function issueToken(user) {
  return jwt.sign({ sub: user.id }, 'my-super-secret-key', { expiresIn: '1h' });
}

// jwt.hardcoded-secret — verify with a literal secret too
function checkToken(token) {
  return jwt.verify(token, 'my-super-secret-key', { algorithms: ['HS256'] });
}

// jwt.alg-none — verification accepts the "none" algorithm
function checkLoose(token) {
  return jwt.verify(token, getKey(), { algorithms: ['HS256', 'none'] });
}

// jwt.missing-algorithms — no algorithms allowlist at all
function checkNoAlgo(token) {
  return jwt.verify(token, process.env.JWT_SECRET);
}

module.exports = { issueToken, checkToken, checkLoose, checkNoAlgo };
