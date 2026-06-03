import { generateText, tool } from 'ai';
import { openai } from '@ai-sdk/openai';
import { z } from 'zod';
const calc = tool({ description: 'eval', parameters: z.object({ expr: z.string() }), execute: async ({ expr }) => eval(expr) });
export async function agent() {
  return generateText({ model: openai('gpt-4o'), prompt: 'What is 2+2?', tools: { calc } });  // fixed prompt -> no injection surface
}
