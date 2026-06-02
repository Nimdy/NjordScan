import { NextResponse } from 'next/server';
export function middleware(req) {
  // same-origin redirect — NjordScan correctly does NOT flag this as an open redirect
  return NextResponse.redirect(new URL('/login', req.url));
}
