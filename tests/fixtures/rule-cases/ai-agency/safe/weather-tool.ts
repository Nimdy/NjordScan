import { tool } from 'ai';
import { z } from 'zod';
export const weather = tool({
  description: 'get weather', parameters: z.object({ city: z.string() }),
  execute: async ({ city }) => ({ city, tempF: 72 }),
});
