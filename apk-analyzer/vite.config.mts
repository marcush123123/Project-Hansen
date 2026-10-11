import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
export default defineConfig(({ command }) => ({
  base: './',
  publicDir: false,
  plugins: [react(), {
    name: 'development-csp',
    transformIndexHtml(html) {
      // React Refresh injects an inline development preamble; production keeps strict script CSP.
      return command === 'serve' ? html.replace("script-src 'self'", "script-src 'self' 'unsafe-inline'") : html;
    },
  }],
  build: { target: 'chrome140', outDir: 'dist/renderer' },
  server: { host: '127.0.0.1', port: 5173, strictPort: true },
  preview: { host: '127.0.0.1', port: 5173, strictPort: true },
}));
