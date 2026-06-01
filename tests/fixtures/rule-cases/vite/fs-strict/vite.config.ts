import { defineConfig } from 'vite';

// VULNERABLE: fs.strict disabled lets the dev server escape the project root.
export default defineConfig({
  server: {
    fs: {
      strict: false,
    },
  },
});
