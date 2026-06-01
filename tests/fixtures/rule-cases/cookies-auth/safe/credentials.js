import bcrypt from 'bcrypt';

// Real password verification against a stored hash. Should NOT fire.
export async function checkPassword(req, user) {
  return bcrypt.compare(req.body.password, user.passwordHash);
}

// Auth header built from env at runtime. Should NOT fire.
export async function callApi() {
  const token = process.env.API_TOKEN;
  return fetch('https://api.internal/data', {
    headers: { Authorization: `Bearer ${token}` },
  });
}

// Basic header from env credentials. Should NOT fire.
export function basicHeader() {
  const creds = Buffer.from(`${process.env.API_USER}:${process.env.API_PASS}`).toString('base64');
  return 'Basic ' + creds;
}
