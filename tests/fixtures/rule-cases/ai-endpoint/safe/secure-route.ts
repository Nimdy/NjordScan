// SAFE: a route handler that checks auth, rate-limits, reads a server-only key,
// and caps the output. None of the ai.* endpoint rules should fire here.
import OpenAI from 'openai';
import { getServerSession } from 'next-auth';
import { Ratelimit } from '@upstash/ratelimit';
import { Redis } from '@upstash/redis';

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY }); // server-only env var
const ratelimit = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(10, '60 s'),
});

export async function POST(req: Request) {
  const session = await getServerSession();
  if (!session) return new Response('Unauthorized', { status: 401 });

  const { success } = await ratelimit.limit(session.user?.email ?? 'anon');
  if (!success) return new Response('Too Many Requests', { status: 429 });

  const { messages } = await req.json();
  const completion = await openai.chat.completions.create({
    model: 'gpt-4o-mini',
    max_tokens: 500, // output is capped
    messages,
  });
  return Response.json(completion);
}
