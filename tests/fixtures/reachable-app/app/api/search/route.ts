import { runQuery } from '../../../lib/db';
export async function GET(req: Request) {
  const q = new URL(req.url).searchParams.get('q');
  return Response.json(await runQuery(q));
}
