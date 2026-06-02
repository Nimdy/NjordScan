// VULNERABLE: SQL built by string concatenation.
const { db } = require('./db');

function getUser(id) {
  return db.query('SELECT * FROM users WHERE id = ' + id);
}

function search(name) {
  return db.execute('SELECT * FROM products WHERE name = "' + name + '"');
}

module.exports = { getUser, search };
