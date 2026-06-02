/**
 * Session management.
 *
 * A session id is a CSPRNG token. The cookie that carries it is hardened:
 * httpOnly (no JS access), secure (HTTPS only), and sameSite=lax (CSRF
 * defence). We store the session server-side keyed by a SHA-256 hash of the
 * token, so a leaked database row cannot be replayed as a live cookie.
 */

import 'server-only';

import { cookies } from 'next/headers';

import { generateId, sha256 } from './crypto';

const SESSION_COOKIE = 'sid';
const SESSION_TTL_SECONDS = 60 * 60 * 8; // 8 hours

export interface SessionRecord {
  userId: string;
  expiresAt: number;
}

// In-memory session store keyed by the HASH of the token (demo storage).
const sessionStore = new Map<string, SessionRecord>();

/** Create a session for a user and set a hardened cookie carrying its token. */
export function createSession(userId: string): void {
  const token = generateId(32);
  const expiresAt = Date.now() + SESSION_TTL_SECONDS * 1000;
  sessionStore.set(sha256(token), { userId, expiresAt });

  const cookieStore = cookies();
  cookieStore.set(SESSION_COOKIE, token, {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    path: '/',
    maxAge: SESSION_TTL_SECONDS,
  });
}

/** Resolve the current user id from the session cookie, or null if signed out. */
export function getCurrentUserId(): string | null {
  const token = cookies().get(SESSION_COOKIE)?.value;
  if (!token) {
    return null;
  }
  const record = sessionStore.get(sha256(token));
  if (!record) {
    return null;
  }
  if (record.expiresAt < Date.now()) {
    sessionStore.delete(sha256(token));
    return null;
  }
  return record.userId;
}

/** Clear the session: drop the server record and expire the cookie. */
export function destroySession(): void {
  const token = cookies().get(SESSION_COOKIE)?.value;
  if (token) {
    sessionStore.delete(sha256(token));
  }
  cookies().delete(SESSION_COOKIE);
}
