# Secure Notes

A small Next.js 14 (App Router) notes app, written the way a security-conscious
team would ship it. It is the **precision target** for the NjordScan simulation
lab: a realistic application that scans with **zero findings**, proving the
scanner is not noisy.

## What makes it secure

| Concern | How it's handled | File |
| --- | --- | --- |
| Security headers | Strict CSP (no `unsafe-inline`/`unsafe-eval`), HSTS, X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy on every route | `next.config.js` |
| Secrets | Read only from `process.env` on the server, validated with zod, never logged or returned. Health check logs only `Boolean(process.env.X)` | `lib/env.ts`, `app/api/health/route.ts` |
| SQL injection | Every query is parameterized (`db.query('... $1', [value])`) — no string building | `lib/db.ts` |
| Sessions | CSPRNG token in an `httpOnly` + `secure` + `sameSite=lax` cookie; server stores only a SHA-256 hash of the token | `lib/session.ts` |
| Authentication | scrypt password verification in constant time; `requireUser` guard fails closed | `lib/auth.ts` |
| Authorization | Every query is scoped to the authenticated `ownerId` | `lib/db.ts`, `app/actions/notes.ts` |
| XSS | User content rendered as escaped React children; no `dangerouslySetInnerHTML` | `components/note-list.tsx` |
| Open redirect | Middleware redirects only to same-origin literal paths | `middleware.ts` |
| Randomness / hashing | `crypto.randomBytes` / `randomUUID` and SHA-256, never `Math.random` or MD5/SHA-1 | `lib/crypto.ts` |
| Outbound links | `target="_blank"` always paired with `rel="noopener noreferrer"` | `app/layout.tsx` |
| Supply chain | Pinned versions, committed lockfile with integrity hashes, no dangerous lifecycle scripts | `package.json`, `package-lock.json` |
| Git hygiene | Real secrets live in `.env.local` (gitignored); only `.env.example` is committed | `.gitignore`, `.env.example` |

## Architecture

Mutations follow the `Client Component → Server Action` pattern. Server Actions
authenticate, validate with zod, and return a typed `ActionResult<T>` with
generic error messages (no stack traces reach the client).

## Running

```bash
cp .env.example .env.local   # fill in real values
npm install
npm run dev
```
