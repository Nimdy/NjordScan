import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

// VULNERABLE: redirects to a destination taken straight from the query string.
export function middleware(req: NextRequest) {
  return NextResponse.redirect(req.nextUrl.searchParams.get('next') ?? '/');
}
