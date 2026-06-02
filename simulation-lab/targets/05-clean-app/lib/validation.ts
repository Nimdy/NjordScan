/**
 * Input validation schemas. Every Server Action validates its untrusted input
 * with one of these before doing any work, so malformed or oversized payloads
 * are rejected at the trust boundary.
 */

import { z } from 'zod';

export const noteInputSchema = z.object({
  title: z.string().trim().min(1).max(120),
  body: z.string().trim().min(1).max(10_000),
});

export type NoteInput = z.infer<typeof noteInputSchema>;

export const credentialsSchema = z.object({
  email: z.string().trim().email().max(254),
  password: z.string().min(12).max(200),
});

export type Credentials = z.infer<typeof credentialsSchema>;

export const noteIdSchema = z.string().uuid();
