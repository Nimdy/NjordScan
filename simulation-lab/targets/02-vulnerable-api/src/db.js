'use strict';

// Tiny in-memory data layer for QuickNotes. In a real deployment `pool` would be
// a pg / mysql2 connection pool; here it's a stub so the app boots without a
// database. The SQL strings are still built the same (bad) way a lot of early
// projects build them, which is the whole point of this lab fixture.

const notes = [
  { id: 1, owner: 'alice', title: 'Groceries', body: 'milk, eggs, bread' },
  { id: 2, owner: 'alice', title: 'Standup', body: 'demo the search page' },
  { id: 3, owner: 'bob', title: 'Ideas', body: 'a notes app, but faster' },
];

// Fake driver — accepts a SQL string, "runs" it, and returns matching notes.
// It does not really parse SQL; it just lets the call sites compile.
const pool = {
  async query(sql, params) {
    // Pretend we executed `sql`. Return a shallow copy so callers can't mutate.
    void sql;
    void params;
    return { rows: notes.map((n) => ({ ...n })) };
  },
  async execute(sql, params) {
    void sql;
    void params;
    return [notes.map((n) => ({ ...n }))];
  },
};

// VULNERABLE: note title comes straight from the request and is concatenated
// into the SQL text. A value like `' OR '1'='1` rewrites the WHERE clause.
async function searchNotesByTitle(req) {
  const term = req.query.title;
  const { rows } = await pool.query(
    "SELECT id, owner, title, body FROM notes WHERE title LIKE '%" + term + "%'"
  );
  return rows;
}

// VULNERABLE: template-literal interpolation into the SQL verb — same SQLi,
// different syntax. `owner` is attacker-controlled.
async function listNotesForOwner(req) {
  const owner = req.query.owner;
  const result = await pool.query(
    `SELECT id, title, body FROM notes WHERE owner = '${owner}' ORDER BY id DESC`
  );
  return result.rows;
}

// VULNERABLE: numeric id concatenated into a DELETE — destructive SQLi.
async function deleteNote(req) {
  const id = req.params.id;
  await pool.execute('DELETE FROM notes WHERE id = ' + id);
  return { deleted: id };
}

module.exports = {
  pool,
  searchNotesByTitle,
  listNotesForOwner,
  deleteNote,
};
