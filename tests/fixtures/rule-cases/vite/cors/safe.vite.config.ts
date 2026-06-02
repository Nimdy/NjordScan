import { defineConfig } from 'vite';

// SAFE: CORS limited to one explicit trusted origin.
export default defineConfig({
  server: {
    cors: { origin: 'http://localhost:3000' },
    port: 5173,
  },
});
