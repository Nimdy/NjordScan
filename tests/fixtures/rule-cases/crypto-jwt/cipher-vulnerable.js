// VULNERABLE: weak/legacy ciphers, hard-coded key material, static IV/salt.
const crypto = require('crypto');

// crypto.deprecated-cipher — createCipher has no IV
function encryptOld(data) {
  const cipher = crypto.createCipher('aes-256-cbc', 'password');
  return cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
}

// crypto.deprecated-cipher — the decipher variant too
function decryptOld(data) {
  const decipher = crypto.createDecipher('aes-256-cbc', 'password');
  return decipher.update(data, 'hex', 'utf8') + decipher.final('utf8');
}

// crypto.weak-cipher — DES
function encryptDes(data, key) {
  return crypto.createCipheriv('des-cbc', key, Buffer.alloc(8));
}

// crypto.weak-cipher — RC4
function encryptRc4(data, key) {
  const algorithm = 'rc4';
  return crypto.createCipheriv(algorithm, key, '');
}

// crypto.weak-cipher — AES in ECB mode
function encryptEcb(data, key) {
  return crypto.createCipheriv('aes-256-ecb', key, null);
}

// crypto.hardcoded-key — key literal passed straight into the cipher
function encryptHardKey(data) {
  const iv = crypto.randomBytes(16);
  return crypto.createCipheriv('aes-256-cbc', 'abcdef0123456789abcdef0123456789', iv);
}

// crypto.hardcoded-iv — static IV constant
function encryptStaticIv(data, key) {
  const iv = '1234567890123456';
  return crypto.createCipheriv('aes-256-cbc', key, iv);
}

// crypto.hardcoded-iv — static salt for key derivation
function deriveKey(password) {
  const salt = 'static-salt-value';
  return crypto.scryptSync(password, salt, 32);
}

module.exports = {
  encryptOld, decryptOld, encryptDes, encryptRc4,
  encryptEcb, encryptHardKey, encryptStaticIv, deriveKey,
};
