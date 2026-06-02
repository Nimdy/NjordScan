#!/usr/bin/env bash
#
# build-history.sh — materialize a self-contained, throwaway git repo whose
# 3-commit history (by THREE different authors) demonstrates NjordScan's
# 🔑 Keystone analysis: the commit that ARMED a kill chain whose other links
# were already in the repo, planted months earlier by someone else.
#
# The story this repo tells:
#
#   commit 1  (Alice)  adds a Next.js API route that builds a SQL query from
#                      ?q=... via a template literal — a latent SQL-injection
#                      sink. It is NOT exploitable yet: the route is auth-gated,
#                      so only logged-in users reach the sink. Alice also,
#                      sloppily, commits a real .env full of secrets.
#
#   commit 2  (Carol)  adds an unrelated rate-limiter helper. Touches nothing
#                      on the vulnerable route. A normal, innocent change.
#
#   commit 3  (Bob)    "temporarily disable auth for staging" — stubs the route
#                      guard to  const isAuthenticated = (req) => true;
#                      Bob's diff contains NO injection and NO database call.
#                      In isolation a PR reviewer would wave it through.
#
# Bob's one-liner is the KEYSTONE: it supplies the missing link
# (no-auth) to Alice's pre-existing SQLi sink ON THE SAME ROUTE, completing an
# unauthenticated-injection chain that existed in neither HEAD~1 nor in either
# author's diff alone. NjordScan reconstructs the tree before Bob's commit,
# re-runs the exact attack-path synthesis, and reports the set-difference:
# a chain that exists AFTER but not BEFORE, attributing the pre-existing SQLi
# link to Alice by git blame.
#
# Usage:   bash build-history.sh [target-dir]
# Default target dir: /tmp/njord-keystone
#
# This script creates an isolated repo OUTSIDE the NjordScan source tree so it
# never nests a .git inside the parent repository.
set -euo pipefail

# ── locate the njordscan CLI ─────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# simulation-lab/targets/04-keystone-repo -> repo root is three levels up.
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
NJORDSCAN="${NJORDSCAN:-$REPO_ROOT/.venv/bin/njordscan}"
if [[ ! -x "$NJORDSCAN" ]]; then
  # fall back to whatever njordscan is on PATH
  NJORDSCAN="$(command -v njordscan || true)"
fi
if [[ -z "${NJORDSCAN:-}" || ! -x "$NJORDSCAN" ]]; then
  echo "ERROR: could not find the njordscan CLI. Set NJORDSCAN=/path/to/njordscan." >&2
  exit 1
fi

# Keep every scan's state in a throwaway home so we never touch the user's config
# or pollute the parent repo's .njordscan history.
export NJORDSCAN_HOME="${NJORDSCAN_HOME:-/tmp/njs-keystone-home-$$}"

TARGET_DIR="${1:-/tmp/njord-keystone}"

# ── start from a clean slate ─────────────────────────────────────────────────
echo "==> Building throwaway keystone repo in: $TARGET_DIR"
rm -rf "$TARGET_DIR"
mkdir -p "$TARGET_DIR"

# Run all git in a hermetic environment: no user/global config bleed-through,
# no GPG signing, deterministic identity per commit.
GIT() { git -C "$TARGET_DIR" "$@"; }
git_commit_as() {
  # $1 = author name, $2 = author email, $3 = message, $4 = author date
  local name="$1" email="$2" msg="$3" when="$4"
  GIT add -A
  GIT_AUTHOR_NAME="$name"     GIT_AUTHOR_EMAIL="$email"   GIT_AUTHOR_DATE="$when" \
  GIT_COMMITTER_NAME="$name"  GIT_COMMITTER_EMAIL="$email" GIT_COMMITTER_DATE="$when" \
    GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
    git -C "$TARGET_DIR" commit -q -m "$msg"
}

GIT init -q
GIT config user.name  "build-history"
GIT config user.email "build@example.test"
GIT config commit.gpgsign false
GIT config core.autocrlf false

# ─────────────────────────────────────────────────────────────────────────────
# COMMIT 1 — Alice: a Next.js app skeleton + the auth-gated search route with a
#            latent SQLi sink, plus a carelessly committed .env.
# ─────────────────────────────────────────────────────────────────────────────
mkdir -p "$TARGET_DIR/app/api/products" "$TARGET_DIR/lib"

cat > "$TARGET_DIR/package.json" <<'JSON'
{
  "name": "storefront",
  "version": "0.4.2",
  "private": true,
  "scripts": {
    "dev": "next dev",
    "build": "next build",
    "start": "next start"
  },
  "dependencies": {
    "next": "14.2.3",
    "react": "18.3.1",
    "react-dom": "18.3.1",
    "pg": "8.11.5"
  }
}
JSON

cat > "$TARGET_DIR/next.config.js" <<'JS'
/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
};
module.exports = nextConfig;
JS

cat > "$TARGET_DIR/lib/db.js" <<'JS'
// Thin wrapper around the Postgres connection pool used across the app.
import { Pool } from "pg";

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

export const db = {
  // NOTE: callers are expected to parameterize. Historically some routes have
  // interpolated user input directly — see app/api/products/route.js.
  query: (text, params) => pool.query(text, params),
};
JS

cat > "$TARGET_DIR/lib/auth.js" <<'JS'
// Session helper shared by the protected API routes. Reads the signed session
// cookie and tells the route whether the caller is a logged-in customer.
import { cookies } from "next/headers";
import { verifySession } from "./session";

export function getSessionUser(req) {
  const token = cookies().get("session")?.value;
  if (!token) return null;
  return verifySession(token);
}
JS

cat > "$TARGET_DIR/lib/session.js" <<'JS'
// Verifies the HMAC-signed session token. Real implementation lives in the
// platform package; this is the storefront's thin adapter.
import crypto from "crypto";

export function verifySession(token) {
  const [payload, sig] = String(token).split(".");
  if (!payload || !sig) return null;
  const expected = crypto
    .createHmac("sha256", process.env.SESSION_SECRET || "dev")
    .update(payload)
    .digest("hex");
  if (sig !== expected) return null;
  try {
    return JSON.parse(Buffer.from(payload, "base64").toString("utf8"));
  } catch {
    return null;
  }
}
JS

# The vulnerable route, in its ORIGINAL (auth-gated) form. The SQLi sink is here
# from day one, but it is gated behind a real auth check, so it is not an
# *unauthenticated* injection chain yet.
cat > "$TARGET_DIR/app/api/products/route.js" <<'JS'
import { db } from "@/lib/db";
import { getSessionUser } from "@/lib/auth";

// Only logged-in customers may search the catalog (it exposes internal SKUs).
const isAuthenticated = (req) => getSessionUser(req) !== null;

export async function GET(req) {
  if (!isAuthenticated(req)) {
    return new Response("Unauthorized", { status: 401 });
  }

  const url = new URL(req.url);
  const q = url.searchParams.get("q") || "";

  // TODO: parameterize this — building it inline for now to ship the demo.
  const rows = await db.query(
    `SELECT id, name, price FROM products WHERE name ILIKE '%${q}%' ORDER BY name`
  );

  return Response.json(rows.rows);
}
JS

# Alice carelessly commits the real .env (git-hygiene finding).
cat > "$TARGET_DIR/.env" <<'ENV'
# Storefront environment — DO NOT COMMIT (but we did).
DATABASE_URL=postgres://storefront:S3cr3tP%40ss@db.internal:5432/storefront
SESSION_SECRET=2f9b1c7e4a8d0f63b5e2a1c9d7f4e6b8
STRIPE_SECRET_KEY=sk_live_51Mq8aLKj3nХReal0LookingKeyDataABCDEF1234
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
ENV

cat > "$TARGET_DIR/README.md" <<'MD'
# storefront

Internal product catalog for the storefront. Next.js App Router + Postgres.

## API

- `GET /api/products?q=...` — search the catalog (logged-in customers only).

## Local dev

Copy `.env.example` to `.env` and fill in the secrets, then `npm run dev`.
MD

cat > "$TARGET_DIR/.env.example" <<'ENV'
DATABASE_URL=
SESSION_SECRET=
STRIPE_SECRET_KEY=
AWS_SECRET_ACCESS_KEY=
ENV

git_commit_as "Alice Nguyen" "alice@storefront.test" \
  "feat(api): add product catalog search route" \
  "2026-02-03T10:14:00-05:00"

# ─────────────────────────────────────────────────────────────────────────────
# COMMIT 2 — Carol: an unrelated rate-limiter helper. Touches nothing on the
#            vulnerable route. This proves Keystone does not blame an innocent,
#            unrelated change.
# ─────────────────────────────────────────────────────────────────────────────
mkdir -p "$TARGET_DIR/lib"
cat > "$TARGET_DIR/lib/rate-limit.js" <<'JS'
// Tiny fixed-window in-memory rate limiter. Good enough for a single node;
// swap for Redis when we scale out. Added to throttle the public marketing
// contact form, unrelated to the catalog API.
const WINDOW_MS = 60_000;
const buckets = new Map();

export function rateLimit(key, max = 30) {
  const now = Date.now();
  const slot = Math.floor(now / WINDOW_MS);
  const id = `${key}:${slot}`;
  const count = (buckets.get(id) || 0) + 1;
  buckets.set(id, count);

  // opportunistic cleanup of stale slots
  if (buckets.size > 10_000) {
    for (const k of buckets.keys()) {
      if (!k.endsWith(`:${slot}`)) buckets.delete(k);
    }
  }
  return count <= max;
}
JS

git_commit_as "Carol Diaz" "carol@storefront.test" \
  "feat(lib): add fixed-window rate limiter for contact form" \
  "2026-03-18T16:41:00-05:00"

# ─────────────────────────────────────────────────────────────────────────────
# COMMIT 3 — Bob: "temporarily disable auth for staging" — the KEYSTONE.
#            Stubs the route's guard to always return true. No injection, no DB
#            call in this diff — yet it arms Alice's pre-existing SQLi sink into
#            a complete UNAUTHENTICATED injection chain.
# ─────────────────────────────────────────────────────────────────────────────
cat > "$TARGET_DIR/app/api/products/route.js" <<'JS'
import { db } from "@/lib/db";
import { getSessionUser } from "@/lib/auth";

// TEMP: staging has no session provider wired up yet, so the auth check 500s.
// Disabling it so QA can test catalog search. Re-enable before prod!  -bob
const isAuthenticated = (req) => true;

export async function GET(req) {
  if (!isAuthenticated(req)) {
    return new Response("Unauthorized", { status: 401 });
  }

  const url = new URL(req.url);
  const q = url.searchParams.get("q") || "";

  // TODO: parameterize this — building it inline for now to ship the demo.
  const rows = await db.query(
    `SELECT id, name, price FROM products WHERE name ILIKE '%${q}%' ORDER BY name`
  );

  return Response.json(rows.rows);
}
JS

git_commit_as "Bob Carter" "bob@storefront.test" \
  "chore(api): temporarily disable auth on product search for staging" \
  "2026-05-29T09:05:00-05:00"

# ─────────────────────────────────────────────────────────────────────────────
# Show the history, then run NjordScan in --diff mode against Bob's commit.
# ─────────────────────────────────────────────────────────────────────────────
echo
echo "==> Commit history (3 authors):"
GIT --no-pager log --pretty=format:'  %h  %an  —  %s' --reverse
echo
echo
echo "==> Scanning Bob's commit (HEAD) vs its parent with --diff HEAD~1"
echo "    \$ njordscan scan $TARGET_DIR --diff HEAD~1"
echo

# The 🔑 Keystone block renders in terminal format. Run it and let it stream.
"$NJORDSCAN" scan "$TARGET_DIR" --diff HEAD~1 || true

echo
echo "==> (machine-readable) keystone_paths from the same scan in JSON:"
"$NJORDSCAN" scan "$TARGET_DIR" --diff HEAD~1 --format json 2>/dev/null \
  | "$REPO_ROOT/.venv/bin/python" "$SCRIPT_DIR/print_keystone.py" || true

echo
echo "==> Done. The repo lives at: $TARGET_DIR"
echo "    Re-run any time:  bash build-history.sh $TARGET_DIR"
