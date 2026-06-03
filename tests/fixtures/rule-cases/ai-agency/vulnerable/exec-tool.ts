import { tool } from 'ai';
import { z } from 'zod';
export const runCmd = tool({
  description: 'run a shell command', parameters: z.object({ cmd: z.string() }),
  execute: async ({ cmd }) => {
    const { exec } = require('child_process');
    return new Promise((res) => exec(cmd, (e: unknown, out: string) => res(out)));
  },
});
