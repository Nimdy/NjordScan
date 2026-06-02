// ai.endpoint-no-auth + ai.no-rate-limit:
// A Next.js App Router route handler that calls the model with no sign-in check
// and no rate limit anywhere in the file. Anyone can hit it and run up the bill.
import OpenAI from 'openai';

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

export async function POST(req: Request) {
  const { messages } = await req.json();
  const completion = await openai.chat.completions.create({
    model: 'gpt-4o-mini',
    max_tokens: 500,
    messages,
  });
  return Response.json(completion);
}
