// SAFE: a strict CSP using a per-request nonce, no unsafe-* tokens.
import { randomBytes } from 'crypto';

export default function handler(req, res) {
  const nonce = randomBytes(16).toString('base64');
  res.setHeader(
    'Content-Security-Policy',
    `default-src 'self'; script-src 'self' 'nonce-${nonce}'; object-src 'none'; base-uri 'self'`
  );
  res.send(`<h1>hello</h1>`);
}
