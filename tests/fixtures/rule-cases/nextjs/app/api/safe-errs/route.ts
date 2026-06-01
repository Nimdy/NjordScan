// SAFE: logs the full error on the server, returns only a generic message.
export async function GET() {
  try {
    throw new Error('boom');
  } catch (err) {
    console.error(err); // full detail (including err.stack) stays server-side
    return Response.json({ error: 'Something went wrong' }, { status: 500 });
  }
}
