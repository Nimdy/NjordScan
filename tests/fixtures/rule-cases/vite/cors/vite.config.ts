import { defineConfig } from 'vite';

// VULNERABLE: wildcard CORS on the dev server.
export default defineConfig({
  server: {
    cors: true,
    port: 5173,
  },
});
