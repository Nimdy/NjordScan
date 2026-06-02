import { defineConfig } from 'vite';

// VULNERABLE: server.fs.allow opened to the whole filesystem.
export default defineConfig({
  server: {
    fs: {
      allow: ['/', '..'],
    },
  },
});
