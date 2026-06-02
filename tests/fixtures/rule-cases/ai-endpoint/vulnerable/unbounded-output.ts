// ai.unbounded-output: model call with no max-token cap. (This file also has
// auth + rate limit so ONLY the unbounded-output rule should fire here.)
import OpenAI from 'openai';
import { getServerSession } from 'next-auth';
import { Ratelimit } from '@upstash/ratelimit';
import { Redis } from '@upstash/redis';

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const ratelimit = new Ratelimit({ redis: Redis.fromEnv(), limiter: Ratelimit.slidingWindow(10, '60 s') });

export async function POST(req: Request) {
  const session = await getServerSession();
  if (!session) return new Response('Unauthorized', { status: 401 });

  const { success } = await ratelimit.limit('user');
  if (!success) return new Response('Too Many Requests', { status: 429 });

  const { messages } = await req.json();
  const completion = await openai.chat.completions.create({
    model: 'gpt-4o',
    messages,
  });
  return Response.json(completion);
}
