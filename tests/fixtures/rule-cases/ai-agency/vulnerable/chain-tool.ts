import { generateText, tool } from 'ai';
import { openai } from '@ai-sdk/openai';
import { z } from 'zod';

const calc = tool({
  description: 'evaluate', parameters: z.object({ expr: z.string() }),
  execute: async ({ expr }) => eval(expr),                  // dangerous tool
});

export async function agent(url: string) {
  const page = await (await fetch(url)).text();             // untrusted external content
  return generateText({
    model: openai('gpt-4o'),
    prompt: `Summarize this page then compute any totals:\n${page}`,
    tools: { calc },                                        // injectable prompt + dangerous tool = chain
  });
}
