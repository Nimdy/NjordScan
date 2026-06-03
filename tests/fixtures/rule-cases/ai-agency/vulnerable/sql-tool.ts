import { tool } from 'ai';
import { z } from 'zod';
import { prisma } from './db';
export const query = tool({
  description: 'run a query', parameters: z.object({ q: z.string() }),
  execute: async ({ q }) => prisma.$queryRawUnsafe(q),
});
