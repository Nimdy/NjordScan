import { cookies } from 'next/headers';

// cookie.missing-httponly via Next.js cookies().set
export function setSessionNext(token: string) {
  cookies().set('session', token, { secure: true, sameSite: 'lax' });
}

// cookie.missing-secure via response.cookies.set
export function setSessionResponse(response: any, token: string) {
  response.cookies.set('auth_token', token, { httpOnly: true, sameSite: 'lax' });
}
