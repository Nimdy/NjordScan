'use client';

import { useState, useTransition } from 'react';

import { signInAction } from '@/app/actions/auth';

/**
 * Client component for the sign-in form. On success the Server Action redirects;
 * on failure it returns a generic message we render as plain text (React escapes
 * it, so there is no XSS surface).
 */
export function LoginForm(): JSX.Element {
  const [error, setError] = useState<string | null>(null);
  const [isPending, startTransition] = useTransition();

  function onSubmit(formData: FormData): void {
    setError(null);
    startTransition(async () => {
      const result = await signInAction(formData);
      // A returned result only ever means failure; success redirects server-side.
      if (result && result.success === false) {
        setError(result.error);
      }
    });
  }

  return (
    <form action={onSubmit}>
      <label htmlFor="email">Email</label>
      <input id="email" name="email" type="email" autoComplete="username" required />

      <label htmlFor="password">Password</label>
      <input
        id="password"
        name="password"
        type="password"
        autoComplete="current-password"
        required
      />

      {error ? <p role="alert">{error}</p> : null}

      <button type="submit" disabled={isPending}>
        {isPending ? 'Signing in…' : 'Sign in'}
      </button>
    </form>
  );
}
