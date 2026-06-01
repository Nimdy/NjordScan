// VULNERABLE: returns the error stack trace to the client.
export async function GET() {
  try {
    throw new Error('boom');
  } catch (err) {
    return Response.json({ error: err.stack }, { status: 500 });
  }
}
