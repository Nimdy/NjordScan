import { defineConfig } from 'vite';

// VULNERABLE: dev server bound to all network interfaces.
export default defineConfig({
  server: {
    host: true,
    port: 5173,
  },
});
