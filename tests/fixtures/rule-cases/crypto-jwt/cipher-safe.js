// SAFE: modern authenticated encryption, random IV/salt, key from env.
const crypto = require('crypto');

// createCipheriv (the safe variant, has 'iv') -> deprecated-cipher must NOT fire
// key from env -> hardcoded-key must NOT fire
// random iv -> hardcoded-iv must NOT fire
function encrypt(data) {
  const key = Buffer.from(process.env.ENCRYPTION_KEY, 'base64');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);
  return { iv, tag: cipher.getAuthTag(), data: enc };
}

// random salt -> hardcoded-iv must NOT fire
function deriveKey(password) {
  const salt = crypto.randomBytes(16);
  return crypto.scryptSync(password, salt, 32);
}

module.exports = { encrypt, deriveKey };
