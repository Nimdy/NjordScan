// SAFE: parameterized query, value passed separately.
const { db } = require('./db');

function getUser(id) {
  return db.query('SELECT * FROM users WHERE id = ?', [id]);
}

function search(name) {
  return db.execute('SELECT * FROM products WHERE name = $1', [name]);
}

module.exports = { getUser, search };
