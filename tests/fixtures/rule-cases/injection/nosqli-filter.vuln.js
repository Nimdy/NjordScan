// VULNERABLE: req.body passed straight into a database filter.
const User = require('./user-model');

async function login(req, res) {
  const user = await User.findOne(req.body); // {"password": {"$ne": null}} bypasses auth
  res.json({ ok: Boolean(user) });
}

module.exports = { login };
