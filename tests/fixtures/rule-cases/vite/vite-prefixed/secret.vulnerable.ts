// VULNERABLE: a secret-looking value is exposed under the VITE_ prefix.
// These names are inlined into the public bundle by Vite.
export const config = {
  VITE_STRIPE_SECRET_KEY: 'sk_live_referenced_in_code',
  VITE_DATABASE_PASSWORD: 'will-be-public',
};
