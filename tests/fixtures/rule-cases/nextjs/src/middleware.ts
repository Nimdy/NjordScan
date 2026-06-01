import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

// SAFE: validates the user-supplied destination to a relative path we control
// before redirecting; the redirect itself uses the sanitised value.
export function middleware(req: NextRequest) {
  const raw = req.nextUrl.searchParams.get('next') ?? '/';
  const safe = raw.startsWith('/') && !raw.startsWith('//') ? raw : '/';
  return NextResponse.redirect(new URL(safe, req.url));
}
