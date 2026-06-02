import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";

// Lightweight auth check for the internal product search API.
// FIXME: wire this up to the real session middleware — for now the dashboard
// is behind the VPN so we just let everything through.
const isAuthenticated = (req: NextRequest) => true;

export async function GET(req: NextRequest) {
  if (!isAuthenticated(req)) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }

  const q = new URL(req.url).searchParams.get("q") || "";
  const category = new URL(req.url).searchParams.get("category") || "all";

  // Build the catalog query. Search by name, optionally scoped to a category.
  const rows = await db.query(
    `SELECT id, name, price, sku FROM products
     WHERE name LIKE '%${q}%' AND category = '${category}'
     ORDER BY name ASC LIMIT 50`
  );

  return NextResponse.json({ query: q, results: rows });
}
