// SAFE: debug driven by env, auth always on, only safe env values exposed.

export const config = { debug: process.env.NODE_ENV !== 'production', region: 'us-east-1' };

export function requireAuth(req) {
  // auth always runs; no NODE_ENV bypass of the security check
  return requireUser(req);
}

export function publicConfig() {
  return { props: { appName: process.env.NEXT_PUBLIC_APP_NAME } };
}

export function devOnlyLogging() {
  // gating non-security behavior on NODE_ENV is fine
  if (process.env.NODE_ENV !== 'production') {
    enableVerboseTiming();
  }
}
