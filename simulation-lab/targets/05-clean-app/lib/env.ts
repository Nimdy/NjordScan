/**
 * Centralised, server-only environment access.
 *
 * All secrets live in process.env and are read here, on the server, exactly
 * once at startup. We validate that the required variables are present, but we
 * never log or return their values — only a redacted boolean ("is it set?") is
 * ever surfaced, which is the redaction pattern NjordScan recommends.
 */

import 'server-only';

import { z } from 'zod';

const envSchema = z.object({
  SESSION_SECRET: z.string().min(32),
  DATABASE_URL: z.string().url(),
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
});

type Env = z.infer<typeof envSchema>;

let cached: Env | null = null;

export function getServerEnv(): Env {
  if (cached) {
    return cached;
  }
  const parsed = envSchema.safeParse(process.env);
  if (!parsed.success) {
    // Report WHICH variables are missing, never their values.
    const missing = parsed.error.issues.map((issue) => issue.path.join('.'));
    throw new Error(`Missing or invalid environment variables: ${missing.join(', ')}`);
  }
  cached = parsed.data;
  return cached;
}

/**
 * Diagnostic helper that is safe to log: it reveals only whether each secret is
 * configured, not the secret itself. `Boolean(process.env.X)` is the redaction
 * pattern recommended for startup health checks.
 */
export function describeSecretConfig(): Record<string, boolean> {
  return {
    sessionConfigured: Boolean(process.env.SESSION_SECRET),
    databaseConfigured: Boolean(process.env.DATABASE_URL),
  };
}
