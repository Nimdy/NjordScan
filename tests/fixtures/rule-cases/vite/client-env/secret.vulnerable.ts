// VULNERABLE: a secret read from import.meta.env ships to every visitor.
export function createStripeClient() {
  const secret = import.meta.env.VITE_STRIPE_SECRET_KEY;
  return { secret };
}

export const dbPassword = import.meta.env.VITE_DB_PASSWORD;
