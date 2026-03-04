import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import basicSsl from '@vitejs/plugin-basic-ssl';
import path from 'path';

export default defineConfig({
    plugins: [react()],

    resolve: {
        alias: {
            // Resolve workspace packages
            '@mitch/shared-types': path.resolve(__dirname, '../../packages/shared-types/src'),
            '@mitch/shared-crypto': path.resolve(__dirname, '../../packages/shared-crypto/src'),
            '@mitch/policy-engine': path.resolve(__dirname, '../../packages/policy-engine/src'),
            '@mitch/audit-log': path.resolve(__dirname, '../../packages/audit-log/src'),
            '@mitch/secure-storage': path.resolve(__dirname, '../../packages/secure-storage/src'),
            '@mitch/predicates': path.resolve(__dirname, '../../packages/predicates/src'),
            '@mitch/layer-resolver': path.resolve(__dirname, '../../packages/layer-resolver/src'),
        },
    },

    // Optimize dependencies (avoid pre-bundling workspace packages)
    optimizeDeps: {
        exclude: [
            '@mitch/shared-types',
            '@mitch/shared-crypto',
            '@mitch/policy-engine',
            '@mitch/audit-log',
            '@mitch/secure-storage',
            '@mitch/predicates',
            '@mitch/layer-resolver',
        ],
    },

    server: {
        port: 5173,
        strictPort: false, // Allow fallback if port used
        host: true, // Expose to network
        allowedHosts: true, // Allow ngrok/localtunnel/serveo hosts
    },
});
