import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

/**
 * SecureConfigAI frontend build configuration.
 *
 * Dev proxy: requests to `/api/**` and `/health` are forwarded to the backend so
 * the browser never performs a cross-origin request during development. When
 * `VITE_API_BASE_URL` is set (see `.env.example`) the application talks to that
 * absolute origin instead of relying on the proxy.
 */
const DEV_BACKEND_ORIGIN = 'http://127.0.0.1:8001';

export default defineConfig(({ mode }) => {
  // Load every variable ('' prefix) so a developer can inspect the resolved config.
  const env = loadEnv(mode, '.', '');
  const backendOrigin = env.VITE_DEV_BACKEND_ORIGIN || DEV_BACKEND_ORIGIN;

  return {
    plugins: [react()],
    server: {
      port: 5173,
      strictPort: true,
      proxy: {
        '/api': {
          target: backendOrigin,
          changeOrigin: true,
        },
        '/health': {
          target: backendOrigin,
          changeOrigin: true,
        },
        // The contract documents `GET /api/v1/meta`, but the shipped backend
        // mounts the meta router at the application root (`/meta`), so this path
        // must be proxied too — otherwise the request falls through to the SPA
        // fallback and returns index.html instead of JSON.
        '/meta': {
          target: backendOrigin,
          changeOrigin: true,
        },
      },
    },
    build: {
      outDir: 'dist',
      target: 'es2020',
      cssCodeSplit: true,
      sourcemap: false,
      chunkSizeWarningLimit: 700,
      rollupOptions: {
        output: {
          // Keep the framework runtime stable across deploys so route chunks can be
          // cached by the browser independently of application code.
          manualChunks: {
            'vendor-react': ['react', 'react-dom', 'react-router-dom'],
            'vendor-query': ['@tanstack/react-query'],
          },
        },
      },
    },
  };
});
