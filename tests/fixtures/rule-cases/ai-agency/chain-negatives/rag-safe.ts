import { generateText, tool } from 'ai';
import { openai } from '@ai-sdk/openai';
import { z } from 'zod';
const weather = tool({ description: 'weather', parameters: z.object({ city: z.string() }), execute: async ({ city }) => ({ city, tempF: 72 }) });
export async function agent(store: any, q: string) {
  const docs = await store.similaritySearch(q);            // untrusted RAG content
  return generateText({ model: openai('gpt-4o'), prompt: `Use these docs:\n${docs}`, tools: { weather } });  // safe tool -> no chain
}
