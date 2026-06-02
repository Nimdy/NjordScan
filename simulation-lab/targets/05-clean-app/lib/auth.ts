/**
 * Password verification and the authentication guard.
 *
 * Passwords are never stored or compared in plaintext. We derive a key with
 * scrypt (a memory-hard KDF) and compare it in constant time. The guard,
 * `requireUser`, is used by every protected route and Server Action — it fails
 * closed (throws) when there is no valid session.
 */

import 'server-only';

import { scryptSync, timingSafeEqual } from 'node:crypto';

import { getCurrentUserId } from './session';

const SCRYPT_KEYLEN = 64;

interface StoredCredential {
  userId: string;
  salt: string;
  derivedKeyHex: string;
}

/**
 * A tiny demo credential store. In production these rows come from the
 * database; the point here is that we only ever keep a salted scrypt hash,
 * never a plaintext password.
 */
const credentials = new Map<string, StoredCredential>();

export function registerCredential(email: string, salt: string, derivedKeyHex: string): void {
  credentials.set(email.toLowerCase(), {
    userId: email.toLowerCase(),
    salt,
    derivedKeyHex,
  });
}

/** Verify a submitted password against the stored scrypt hash, in constant time. */
export function verifyPassword(email: string, submitted: string): string | null {
  const record = credentials.get(email.toLowerCase());
  if (!record) {
    return null;
  }
  const derived = scryptSync(submitted, record.salt, SCRYPT_KEYLEN);
  const expected = Buffer.from(record.derivedKeyHex, 'hex');
  if (derived.length !== expected.length) {
    return null;
  }
  return timingSafeEqual(derived, expected) ? record.userId : null;
}

/**
 * Authentication guard. Returns the current user id, or throws if the request
 * is not authenticated. Protected routes and actions call this first so access
 * is denied by default.
 */
export function requireUser(): string {
  const userId = getCurrentUserId();
  if (!userId) {
    throw new Error('Unauthorized');
  }
  return userId;
}
