// SAFE: only echo the Origin back when it is on the allowlist.
const ALLOWED = new Set(['https://app.example.com', 'https://admin.example.com']);

export default function handler(req, res) {
  const origin = req.headers.origin;
  if (origin && ALLOWED.has(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
  res.json({ ok: true });
}
