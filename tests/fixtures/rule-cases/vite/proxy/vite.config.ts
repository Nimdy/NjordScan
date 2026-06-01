import { defineConfig } from 'vite';

// VULNERABLE: dev proxy skips upstream TLS verification.
export default defineConfig({
  server: {
    proxy: {
      '/api': {
        target: 'https://api.example.com',
        changeOrigin: true,
        secure: false,
      },
    },
  },
});
