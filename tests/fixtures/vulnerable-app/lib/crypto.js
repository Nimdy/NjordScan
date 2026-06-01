import crypto from 'crypto';
export function hashPassword(pw) {
  return crypto.createHash('md5').update(pw).digest('hex');
}
export function makeToken() {
  return 'tok_' + Math.random().toString(36).slice(2);
}
