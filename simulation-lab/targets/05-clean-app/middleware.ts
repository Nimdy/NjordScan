/**
 * Edge middleware: require a session cookie for everything under /notes.
 *
 * Redirects are always to a same-origin literal path built with `new URL(path,
 * req.url)`, so this can never be turned into an open redirect. We preserve the
 * originally-requested path in a `from` query param, URL-encoded.
 */

import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

const SESSION_COOKIE = 'sid';

export function middleware(request: NextRequest): NextResponse {
  const hasSession = Boolean(request.cookies.get(SESSION_COOKIE)?.value);
  if (hasSession) {
    return NextResponse.next();
  }

  const from = request.nextUrl.pathname;
  // Same-origin literal path: `new URL("/login...", req.url)` can never be an
  // open redirect because the path is a constant and the base is our own URL.
  return NextResponse.redirect(new URL(`/login?from=${encodeURIComponent(from)}`, request.url));
}

export const config = {
  matcher: ['/notes/:path*'],
};
