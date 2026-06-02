import { defineConfig } from 'vite';

// SAFE: proxy keeps TLS verification on (default).
export default defineConfig({
  server: {
    proxy: {
      '/api': {
        target: 'https://api.example.com',
        changeOrigin: true,
      },
    },
  },
});
