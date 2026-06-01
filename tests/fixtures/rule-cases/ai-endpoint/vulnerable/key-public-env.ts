// ai.key-clientside: the OpenAI key is behind a NEXT_PUBLIC_ prefix, so it is
// inlined into the browser bundle and visible to every visitor.
import OpenAI from 'openai';

export const openai = new OpenAI({
  apiKey: process.env.NEXT_PUBLIC_OPENAI_API_KEY,
});
