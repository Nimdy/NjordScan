import { defineConfig } from 'vite';

// SAFE: only a non-secret build constant is inlined.
export default defineConfig({
  define: {
    __APP_VERSION__: JSON.stringify('1.2.3'),
    __BUILD_TARGET__: JSON.stringify('production'),
  },
});
