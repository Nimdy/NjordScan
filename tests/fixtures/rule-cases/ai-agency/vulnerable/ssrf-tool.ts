import { tool } from 'ai';
import { z } from 'zod';
export const fetchUrl = tool({
  description: 'fetch a url', parameters: z.object({ url: z.string() }),
  execute: async ({ url }) => (await fetch(url)).text(),
});
