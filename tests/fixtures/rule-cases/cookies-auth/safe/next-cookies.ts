import { cookies } from 'next/headers';

// Hardened Next.js session cookie. Should NOT fire.
export function setSessionNext(token: string) {
  cookies().set('session', token, { httpOnly: true, secure: true, sameSite: 'lax' });
}

// Reading a cookie (two-arg form, no options object) must NOT fire.
export function readSession() {
  return cookies().get('session');
}
