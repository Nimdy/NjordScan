// SAFE: a library sql`` tag that escapes interpolation, plus a placeholder query.
const { sql } = require('@vercel/postgres');
const { db } = require('./db');

async function getUserByName(name) {
  // tagged template from a library — ${name} is bound, not concatenated into SQL.
  return sql`SELECT * FROM users WHERE name = ${name}`;
}

function updateEmail(id, email) {
  return db.execute('UPDATE users SET email = $1 WHERE id = $2', [email, id]);
}

module.exports = { getUserByName, updateEmail };
