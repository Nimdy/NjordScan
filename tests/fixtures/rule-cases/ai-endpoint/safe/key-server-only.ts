// SAFE: the key is a plain server-only env var (no NEXT_PUBLIC_/VITE_ prefix),
// used only in this server module. Nothing ships to the browser.
import OpenAI from 'openai';

export const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

export const anthropicKey = process.env.ANTHROPIC_API_KEY;
