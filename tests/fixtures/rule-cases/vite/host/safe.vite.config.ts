import { defineConfig } from 'vite';

// SAFE: dev server stays on localhost (host left unset).
export default defineConfig({
  server: {
    port: 5173,
    strictPort: true,
  },
});
