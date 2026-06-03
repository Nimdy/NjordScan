import { tool } from 'ai';
import { z } from 'zod';
export const search = tool({
  description: 'search', parameters: z.object({ q: z.string() }),
  execute: async ({ q }) => (await fetch(`https://api.example.com/s?q=${q}`)).json(),
});
