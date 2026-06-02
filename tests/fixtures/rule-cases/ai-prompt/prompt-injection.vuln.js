// VULNERABLE: user input mixed into the AI's system / instruction string.
import OpenAI from 'openai';
import Anthropic from '@anthropic-ai/sdk';

const openai = new OpenAI();
const anthropic = new Anthropic();

// (1) user data interpolated into a { role: 'system' } content
export async function chatA(req) {
  return openai.chat.completions.create({
    model: 'gpt-4o',
    messages: [
      { role: 'system', content: `You are a support bot. Context: ${req.body.message}` },
      { role: 'user', content: 'hello' },
    ],
  });
}

// (3) a named instructions string built from user input
export async function chatB(req) {
  const systemPrompt = 'You are an assistant. User says: ' + req.body.userMessage;
  return openai.chat.completions.create({
    model: 'gpt-4o',
    messages: [{ role: 'system', content: systemPrompt }],
  });
}

// (4) Anthropic top-level `system` param built from user input
export async function chatC(req) {
  return anthropic.messages.create({
    model: 'claude-3-5-sonnet-20240620',
    max_tokens: 1024,
    system: `Follow these rules. Extra: ${req.body.prompt}`,
    messages: [{ role: 'user', content: 'hi' }],
  });
}
