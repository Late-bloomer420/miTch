import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
    plugins: [react()],
    server: {
        port: 5175,
        proxy: {
            '/api': {
                target: process.env.VERIFIER_BACKEND_URL
                    || `http://localhost:${process.env.VERIFIER_BACKEND_PORT || 3004}`,
                changeOrigin: true,
                rewrite: (path) => path.replace(/^\/api/, '')
            }
        }
    }
})
