import { defineConfig } from 'vite';

// Pages serves this from /hawkeye-siem/, local dev from /.
export default defineConfig({
  base: process.env.GITHUB_ACTIONS ? '/hawkeye-siem/' : '/',
  build: { target: 'es2022' },
});
