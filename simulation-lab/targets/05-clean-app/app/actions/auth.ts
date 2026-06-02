'use server';

/**
 * Authentication Server Actions: sign in and sign out.
 *
 * Sign-in validates the credentials, verifies the password against a salted
 * scrypt hash, and only then establishes a hardened session cookie. We return a
 * single generic error for any failure so we don't reveal whether the email or
 * the password was wrong.
 */

import { redirect } from 'next/navigation';

import { verifyPassword } from '@/lib/auth';
import { createSession, destroySession } from '@/lib/session';
import { credentialsSchema } from '@/lib/validation';

export type SignInResult = { success: false; error: string };

export async function signInAction(formData: FormData): Promise<SignInResult | never> {
  const parsed = credentialsSchema.safeParse({
    email: formData.get('email'),
    password: formData.get('password'),
  });
  if (!parsed.success) {
    return { success: false, error: 'Invalid email or password.' };
  }

  const userId = verifyPassword(parsed.data.email, parsed.data.password);
  if (!userId) {
    return { success: false, error: 'Invalid email or password.' };
  }

  createSession(userId);
  // Same-origin literal path — not an open redirect.
  redirect('/notes');
}

export async function signOutAction(): Promise<never> {
  destroySession();
  redirect('/');
}
