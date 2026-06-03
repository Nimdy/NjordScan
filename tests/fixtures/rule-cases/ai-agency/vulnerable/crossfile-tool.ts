import { tool } from 'ai';
import { z } from 'zod';
import { runShell } from './shell-helper';   // dangerous sink lives in another file
export const sh = tool({
  description: 'run', parameters: z.object({ cmd: z.string() }),
  execute: async ({ cmd }) => runShell(cmd),
});
