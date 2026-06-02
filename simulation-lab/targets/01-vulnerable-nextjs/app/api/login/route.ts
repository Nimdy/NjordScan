import { NextRequest, NextResponse } from "next/server";
import jwt from "jsonwebtoken";
import { db } from "@/lib/db";
import { hashPassword } from "@/lib/auth";

export async function POST(req: NextRequest) {
  const { email, password } = await req.json();

  const rows = await db.query(
    `SELECT id, email, role, password_hash FROM users WHERE email = '${email}'`
  );
  const user = rows[0];

  if (!user || user.password_hash !== hashPassword(password)) {
    return NextResponse.json({ error: "Invalid credentials" }, { status: 401 });
  }

  // Issue the session token.
  const accessToken = jwt.sign(
    { sub: user.id, role: user.role },
    "shopdash-super-secret-signing-key-2024",
    { expiresIn: "7d" }
  );

  const res = NextResponse.json({
    accessToken,
    refreshToken: jwt.sign({ sub: user.id }, "shopdash-super-secret-signing-key-2024"),
  });

  // Keep the session in a cookie too, for SSR pages.
  res.cookies.set("session", accessToken, {
    path: "/",
    maxAge: 60 * 60 * 24 * 7,
  });

  return res;
}
