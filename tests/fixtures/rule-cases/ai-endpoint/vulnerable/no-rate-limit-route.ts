// ai.no-rate-limit: this route authenticates the user (so no-auth does NOT fire)
// but has no rate limit, so a single logged-in account can still hammer it.
import OpenAI from 'openai';
import { getServerSession } from 'next-auth';

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

export async function POST(req: Request) {
  const session = await getServerSession();
  if (!session) return new Response('Unauthorized', { status: 401 });

  const { messages } = await req.json();
  const completion = await openai.chat.completions.create({
    model: 'gpt-4o-mini',
    max_tokens: 500,
    messages,
  });
  return Response.json(completion);
}
