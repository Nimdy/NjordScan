// SAFE: only the expected fields are extracted and coerced to strings.
const User = require('./user-model');

async function login(req, res) {
  const email = String(req.body.email);
  const user = await User.findOne({ email });
  res.json({ ok: Boolean(user) });
}

module.exports = { login };
