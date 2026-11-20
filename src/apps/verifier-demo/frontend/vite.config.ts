import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { askmiDevWalletUrl } from '@askmi/shared-types'

// https://vitejs.dev/config/
export default defineConfig({
    plugins: [react()],
    define: {
        __ASKMI_DEV_WALLET_URL__: JSON.stringify(askmiDevWalletUrl(process.env.ASKMI_DEV_HTTPS)),
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
