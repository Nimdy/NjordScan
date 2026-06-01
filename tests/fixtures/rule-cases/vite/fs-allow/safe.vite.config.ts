import { defineConfig } from 'vite';
import { resolve } from 'node:path';

// SAFE: only a specific sibling package directory is allowed.
export default defineConfig({
  server: {
    fs: {
      allow: [resolve(__dirname, 'shared-ui'), resolve(__dirname, 'packages')],
    },
  },
});
