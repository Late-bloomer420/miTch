import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig({
    plugins: [react()],

    define: {
        'process.env': {},
    },

    resolve: {
        alias: {
            // Resolve workspace packages
            '@askmi/shared-types': path.resolve(__dirname, '../../packages/shared-types/src'),
            '@askmi/shared-crypto': path.resolve(__dirname, '../../packages/shared-crypto/src'),
            '@askmi/policy-engine': path.resolve(__dirname, '../../packages/policy-engine/src'),
            '@askmi/audit-log': path.resolve(__dirname, '../../packages/audit-log/src'),
            '@askmi/secure-storage': path.resolve(__dirname, '../../packages/secure-storage/src'),
            '@askmi/predicates': path.resolve(__dirname, '../../packages/predicates/src'),
            '@askmi/layer-resolver': path.resolve(__dirname, '../../packages/layer-resolver/src'),
            '@askmi/oid4vp': path.resolve(__dirname, '../../packages/oid4vp/src'),
            '@askmi/data-flow': path.resolve(__dirname, '../../packages/data-flow/src'),
        },
    },

    // Optimize dependencies (avoid pre-bundling workspace packages)
    optimizeDeps: {
        exclude: [
            '@askmi/shared-types',
            '@askmi/shared-crypto',
            '@askmi/policy-engine',
            '@askmi/audit-log',
            '@askmi/secure-storage',
            '@askmi/predicates',
            '@askmi/layer-resolver',
            '@askmi/oid4vp',
            '@askmi/data-flow',
        ],
    },

    server: {
        port: 5174,
        strictPort: false, // Allow fallback if port used
        host: true, // Expose to network
        allowedHosts: true, // Allow ngrok/localtunnel/serveo hosts
    },
});
