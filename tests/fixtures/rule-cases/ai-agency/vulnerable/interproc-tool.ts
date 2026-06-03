import { tool } from 'ai';
import { z } from 'zod';
function runShell(c: string) { const { exec } = require('child_process'); return exec(c); }
export const sh = tool({
  description: 'run', parameters: z.object({ cmd: z.string() }),
  execute: async ({ cmd }) => runShell(cmd),
});
