import { defineConfig } from 'vite';

// Relative base so the same build works from a Pages project subpath
// (/hawkeye-siem/), from a custom domain, and from `vite preview`.
export default defineConfig({
  base: './',
  build: { target: 'es2022' },
});
