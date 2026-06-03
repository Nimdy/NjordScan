import { tool } from 'ai';
import { z } from 'zod';
import fs from 'fs/promises';
export const writeNote = tool({
  description: 'save a note', parameters: z.object({ path: z.string(), content: z.string() }),
  execute: async ({ path, content }) => { await fs.writeFile(path, content); return 'ok'; },
});
