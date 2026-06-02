/**
 * Thin data-access layer over a Postgres connection pool.
 *
 * Every query uses parameter placeholders ($1, $2, ...) and passes user input
 * through the values array — never string concatenation or template literals.
 * This keeps user data out of the SQL text, which is what prevents SQL
 * injection.
 */

import 'server-only';

import { getServerEnv } from './env';

export interface Note {
  id: string;
  ownerId: string;
  title: string;
  body: string;
  createdAt: string;
}

interface QueryResult<T> {
  rows: T[];
}

interface Pool {
  query<T>(text: string, values: ReadonlyArray<unknown>): Promise<QueryResult<T>>;
}

let pool: Pool | null = null;

/**
 * Lazily create the connection pool. In a real deployment this would be a `pg`
 * Pool; the connection string is read from the validated server environment and
 * never logged.
 */
async function getPool(): Promise<Pool> {
  if (pool) {
    return pool;
  }
  const { DATABASE_URL } = getServerEnv();
  const { Pool: PgPool } = await import('pg');
  pool = new PgPool({ connectionString: DATABASE_URL }) as unknown as Pool;
  return pool;
}

export async function findNoteById(noteId: string, ownerId: string): Promise<Note | null> {
  const db = await getPool();
  // Parameterized: the SQL text is a constant; the values travel in the array.
  const result = await db.query<Note>(
    'SELECT id, owner_id AS "ownerId", title, body, created_at AS "createdAt" FROM notes WHERE id = $1 AND owner_id = $2',
    [noteId, ownerId],
  );
  return result.rows[0] ?? null;
}

export async function listNotesForOwner(ownerId: string): Promise<Note[]> {
  const db = await getPool();
  const result = await db.query<Note>(
    'SELECT id, owner_id AS "ownerId", title, body, created_at AS "createdAt" FROM notes WHERE owner_id = $1 ORDER BY created_at DESC',
    [ownerId],
  );
  return result.rows;
}

export async function createNote(
  ownerId: string,
  title: string,
  body: string,
): Promise<Note> {
  const db = await getPool();
  const result = await db.query<Note>(
    'INSERT INTO notes (owner_id, title, body) VALUES ($1, $2, $3) RETURNING id, owner_id AS "ownerId", title, body, created_at AS "createdAt"',
    [ownerId, title, body],
  );
  return result.rows[0];
}

export async function deleteNote(noteId: string, ownerId: string): Promise<number> {
  const db = await getPool();
  const result = await db.query<Note>(
    'DELETE FROM notes WHERE id = $1 AND owner_id = $2 RETURNING id',
    [noteId, ownerId],
  );
  return result.rows.length;
}
