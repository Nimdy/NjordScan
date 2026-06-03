import { tool } from 'ai';
import { z } from 'zod';
import { prisma } from './db';
export const search = tool({
  description: 'search users', parameters: z.object({ name: z.string() }),
  execute: async ({ name }) => prisma.user.findMany({ where: { name } }),
});
