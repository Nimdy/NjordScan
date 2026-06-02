// VULNERABLE: wildcard ACAO together with credentials.
export default function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.json({ secret: 'user data' });
}
