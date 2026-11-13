import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
    plugins: [react()],
    define: {
        // The wallet dev server serves HTTP only with ASKMI_DEV_HTTPS=0; follow it.
        __ASKMI_DEV_WALLET_URL__: JSON.stringify(
            process.env.ASKMI_DEV_HTTPS === '0' ? 'http://localhost:5174' : 'https://localhost:5174'
        ),
    },
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
