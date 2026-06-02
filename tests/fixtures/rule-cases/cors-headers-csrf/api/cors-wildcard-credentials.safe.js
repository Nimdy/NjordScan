// SAFE: an explicit allowlist, credentials only for trusted origins.
const ALLOWED = new Set(['https://app.example.com']);

export default function handler(req, res) {
  const origin = req.headers.origin;
  if (origin && ALLOWED.has(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Vary', 'Origin');
  }
  res.json({ ok: true });
}
