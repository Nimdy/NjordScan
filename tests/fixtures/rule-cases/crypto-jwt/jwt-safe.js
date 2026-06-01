// SAFE: correct JWT usage. NONE of these lines should fire.
const jwt = require('jsonwebtoken');

const SECRET = process.env.JWT_SECRET;

// secret from env, not a literal -> jwt.hardcoded-secret must NOT fire
function issueToken(user) {
  return jwt.sign({ sub: user.id }, SECRET, { expiresIn: '15m' });
}

// algorithms allowlist present, no "none" -> alg-none + missing-algorithms must NOT fire
function checkToken(token) {
  return jwt.verify(token, SECRET, { algorithms: ['HS256'] });
}

// RS256 with a pinned algorithm -> still safe
function checkRs(token) {
  return jwt.verify(token, PUBLIC_KEY, { algorithms: ['RS256'] });
}

module.exports = { issueToken, checkToken, checkRs };
