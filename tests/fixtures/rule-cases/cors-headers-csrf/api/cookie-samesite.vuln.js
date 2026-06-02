// VULNERABLE: session cookie set with SameSite=None.
export default function handler(req, res) {
  res.cookie('session', req.body.token, {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
  });
  res.json({ ok: true });
}
