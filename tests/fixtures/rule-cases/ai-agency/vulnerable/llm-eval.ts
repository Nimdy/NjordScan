import { generateText } from 'ai';
import { openai } from '@ai-sdk/openai';
export async function handler(prompt: string) {
  const { text } = await generateText({ model: openai('gpt-4o'), prompt });
  return eval(text);
}
