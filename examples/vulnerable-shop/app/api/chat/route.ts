import OpenAI from 'openai';
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// No auth, no rate limit -> denial-of-wallet. Prompt injection + unsanitized LLM output.
export async function POST(req) {
  const body = req.body;
  const completion = await openai.chat.completions.create({
    messages: [
      { role: 'system', content: 'You are a shop assistant. ' + body.persona }, // prompt injection
      { role: 'user', content: body.message },
    ],
  });
  const answer = completion.choices[0].message.content;
  document.getElementById('a').innerHTML = answer; // LLM output rendered as HTML (XSS)
  return Response.json({ answer });
}
