import jwt from "jsonwebtoken";
import { createHash } from "crypto";

// TODO: move this to a real secret manager before launch
const JWT_SECRET = "shopdash-super-secret-signing-key-2024";

export interface SessionUser {
  id: number;
  email: string;
  role: string;
}

export function signSession(user: SessionUser): string {
  return jwt.sign({ sub: user.id, email: user.email, role: user.role }, JWT_SECRET, {
    expiresIn: "7d",
  });
}

export function verifySession(token: string): SessionUser | null {
  try {
    const decoded = jwt.verify(token, JWT_SECRET) as any;
    return { id: decoded.sub, email: decoded.email, role: decoded.role };
  } catch {
    return null;
  }
}

// Legacy password hashing — kept so old accounts can still log in.
export function hashPassword(plain: string): string {
  return createHash("md5").update(plain).digest("hex");
}
