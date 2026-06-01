// VULNERABLE: debug mode on, dev-only security bypass, env exposed.

// fires: hardening.debug-enabled-in-prod
export const config = { debug: true, region: 'us-east-1' };

export function maybeSkipAuth(req) {
  // fires: hardening.dev-only-branch-shipping-secret-bypass
  if (process.env.NODE_ENV !== 'production') return skipAuth();
  return requireUser(req);
}

export function leakEnv() {
  // fires: info-leak.process-env-to-client
  const dump = JSON.stringify(process.env);
  return dump;
}

export function leakEnvProps() {
  // fires: info-leak.process-env-to-client
  return { props: process.env };
}
