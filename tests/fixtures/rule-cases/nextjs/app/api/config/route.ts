// VULNERABLE: returns the entire process.env to the client.
export async function GET() {
  return Response.json(process.env);
}

// VULNERABLE: spreads process.env into the response object.
export async function POST() {
  return Response.json({ ...process.env, ok: true });
}
