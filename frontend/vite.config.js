import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// Every backend path is proxied so the browser never leaves
// http://localhost:5173. The session cookie is set during the OIDC /callback;
// if the browser touched :8000 directly at any point, the cookie would land
// on that origin and every later API call from this one would be
// unauthenticated. localhost and 127.0.0.1 are different cookie origins —
// the browser side uses localhost consistently, the proxy target uses
// 127.0.0.1 (server-to-server, no cookies involved).
const BACKEND = 'http://127.0.0.1:8000'
const PROXIED = ['/api', '/login', '/logout', '/callback', '/authorize', '/v1', '/config.js']

export default defineConfig({
  // Relative asset paths so the built bundle serves from any origin/path.
  base: './',
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    strictPort: true,
    proxy: Object.fromEntries(PROXIED.map((p) => [p, { target: BACKEND }])),
  },
})
