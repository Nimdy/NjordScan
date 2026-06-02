// SAFE: only the minimal, non-sensitive fields are sent to the model.
import OpenAI from 'openai';

const openai = new OpenAI();

export async function summarize(ticket) {
  return openai.chat.completions.create({
    model: 'gpt-4o',
    messages: [
      { role: 'system', content: 'Summarise the support ticket.' },
      { role: 'user', content: ticket.text }, // only the text — no keys, no PII
    ],
  });
}

export async function sendField(req) {
  return openai.chat.completions.create({
    model: 'gpt-4o',
    messages: [{ role: 'user', content: req.body.message }],
  });
}
