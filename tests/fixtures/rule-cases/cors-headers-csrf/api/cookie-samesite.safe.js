// SAFE: session cookie uses SameSite=Lax.
export default function handler(req, res) {
  res.cookie('session', req.body.token, {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
  });
  res.json({ ok: true });
}
