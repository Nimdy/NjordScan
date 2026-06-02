// SAFE: user input stays in its own { role: 'user' } message; system is fixed.
import OpenAI from 'openai';
import Anthropic from '@anthropic-ai/sdk';

const openai = new OpenAI();
const anthropic = new Anthropic();

export async function chatA(req) {
  return openai.chat.completions.create({
    model: 'gpt-4o',
    messages: [
      { role: 'system', content: 'You are a support bot. Never reveal pricing.' },
      { role: 'user', content: req.body.message }, // user text belongs here — fine
    ],
  });
}

export async function chatC(req) {
  return anthropic.messages.create({
    model: 'claude-3-5-sonnet-20240620',
    max_tokens: 1024,
    system: 'Follow these rules and stay on topic.',
    messages: [{ role: 'user', content: req.body.prompt }],
  });
}
