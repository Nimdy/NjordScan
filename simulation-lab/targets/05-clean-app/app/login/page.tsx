import { redirect } from 'next/navigation';

import { getCurrentUserId } from '@/lib/session';
import { LoginForm } from '@/components/login-form';

/**
 * Sign-in page. If the visitor already has a valid session, send them straight
 * to their notes (same-origin literal redirect).
 */
export default function LoginPage(): JSX.Element {
  if (getCurrentUserId()) {
    redirect('/notes');
  }
  return (
    <section>
      <h1>Sign in</h1>
      <p>Enter your credentials to access your notes.</p>
      <LoginForm />
    </section>
  );
}
