const { defineConfig } = require('vite');
const react = require('@vitejs/plugin-react');

// https://vitejs.dev/config/
module.exports = defineConfig({
    plugins: [react()],
    server: {
        port: 5175,
        strictPort: true, // Fail immediately if 5175 is in use, avoiding prompts
        proxy: {
            '/api': {
                target: process.env.VERIFIER_BACKEND_URL
                    || `http://localhost:${process.env.VERIFIER_BACKEND_PORT || 3002}`,
                changeOrigin: true,
                rewrite: (path) => path.replace(/^\/api/, '')
            }
        }
    }
});
