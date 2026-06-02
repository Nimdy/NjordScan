import { NextResponse } from 'next/server';

// Real auth check. Should NOT fire.
export const isAuthenticated = (req) => Boolean(req.cookies.get('session'));

export function middleware(req) {
  const session = req.cookies.get('session');
  if (!session) {
    return NextResponse.redirect(new URL('/login', req.url));
  }
  return NextResponse.next();
}

// Auth middleware actually wired up. Should NOT fire.
app.use(requireAuth);
app.get('/admin', adminHandler);
