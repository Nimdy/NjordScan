// VULNERABLE: the request Origin is echoed straight back, no allowlist.
export default function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.json({ secret: 'user data' });
}
