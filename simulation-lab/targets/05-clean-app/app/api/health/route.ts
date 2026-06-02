import { NextResponse } from 'next/server';

import { describeSecretConfig } from '@/lib/env';

/**
 * Health/readiness endpoint.
 *
 * It reports whether each required secret is *configured* (a boolean), never
 * the secret values themselves. `Boolean(process.env.X)` is the redaction
 * pattern that keeps a status endpoint from leaking configuration.
 */
export function GET(): NextResponse {
  const config = describeSecretConfig();
  const ready = config.sessionConfigured && config.databaseConfigured;

  // Only booleans are logged — no secret value ever reaches the logs.
  console.info('[health] ready=%s', ready);

  return NextResponse.json({
    status: ready ? 'ok' : 'degraded',
    checks: config,
  });
}
