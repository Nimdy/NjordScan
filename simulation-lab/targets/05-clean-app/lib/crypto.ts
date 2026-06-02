/**
 * Cryptographic helpers built on Node's `crypto` module.
 *
 * - Random identifiers use crypto.randomBytes / randomUUID (a CSPRNG), never
 *   Math.random.
 * - Hashing uses SHA-256, never MD5 or SHA-1.
 * - Comparisons of secrets use timingSafeEqual to avoid timing side channels.
 */

import 'server-only';

import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';

/** A cryptographically secure, URL-safe random identifier. */
export function generateId(byteLength = 32): string {
  return randomBytes(byteLength).toString('base64url');
}

/** A v4 UUID from the platform CSPRNG. */
export function newUuid(): string {
  return randomUUID();
}

/** SHA-256 hex digest of an input. */
export function sha256(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}

/** Constant-time string comparison; returns false for length mismatches. */
export function safeEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) {
    return false;
  }
  return timingSafeEqual(bufA, bufB);
}
