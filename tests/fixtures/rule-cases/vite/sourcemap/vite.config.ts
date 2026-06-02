import { defineConfig } from 'vite';

// VULNERABLE: production build ships public source maps.
export default defineConfig({
  build: {
    sourcemap: true,
    outDir: 'dist',
  },
});
