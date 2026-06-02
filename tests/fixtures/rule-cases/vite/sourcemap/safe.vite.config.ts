import { defineConfig } from 'vite';

// SAFE: no public source maps in production.
export default defineConfig({
  build: {
    sourcemap: false,
    outDir: 'dist',
  },
});
