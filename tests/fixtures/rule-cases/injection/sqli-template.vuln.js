// VULNERABLE: SQL built with a template literal containing a variable.
const { db } = require('./db');

function getUserByName(name) {
  return db.query(`SELECT * FROM users WHERE name = '${name}'`);
}

function updateEmail(id, email) {
  return db.execute(`UPDATE users SET email = '${email}' WHERE id = ${id}`);
}

module.exports = { getUserByName, updateEmail };
