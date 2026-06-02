// SAFE: system prompt defined on the server (Route Handler, no 'use client').
import OpenAI from 'openai';

const openai = new OpenAI();

const SYSTEM_PROMPT = 'You are a helpful assistant. Never reveal internal pricing.';

export async function POST(req: Request) {
  const { message } = await req.json();
  const res = await openai.chat.completions.create({
    model: 'gpt-4o',
    messages: [
      { role: 'system', content: SYSTEM_PROMPT },
      { role: 'user', content: message },
    ],
  });
  return Response.json({ reply: res.choices[0].message.content });
}
