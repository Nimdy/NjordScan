import { tool } from 'ai';
import { z } from 'zod';
export const calc = tool({
  description: 'evaluate', parameters: z.object({ expr: z.string() }),
  execute: async ({ expr }) => eval(expr),
});
