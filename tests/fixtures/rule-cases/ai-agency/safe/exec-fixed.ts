import { tool } from 'ai';
import { z } from 'zod';
export const listFiles = tool({
  description: 'list', parameters: z.object({}),
  execute: async () => { const { execSync } = require('child_process'); return execSync('ls -la').toString(); },
});
