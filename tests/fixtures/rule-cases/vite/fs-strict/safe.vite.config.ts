import { defineConfig } from 'vite';

// SAFE: strict mode kept on (the default).
export default defineConfig({
  server: {
    fs: {
      strict: true,
    },
  },
});
