import { defineConfig } from 'vite';

// VULNERABLE: `define` inlines a secret / process.env into the public bundle.
export default defineConfig({
  define: {
    'process.env': process.env,
    __API_SECRET__: JSON.stringify(process.env.API_SECRET),
    'process.env.STRIPE_SECRET_KEY': JSON.stringify(process.env.STRIPE_SECRET_KEY),
  },
});
