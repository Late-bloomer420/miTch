import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

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
            '@mitch/oid4vp': path.resolve(__dirname, '../../packages/oid4vp/src'),
            '@mitch/data-flow': path.resolve(__dirname, '../../packages/data-flow/src'),
            '@mitch/mdoc': path.resolve(__dirname, '../../packages/mdoc/src'),
        },
    },

    optimizeDeps: {
        exclude: [
            '@mitch/shared-types',
            '@mitch/shared-crypto',
            '@mitch/policy-engine',
            '@mitch/audit-log',
            '@mitch/secure-storage',
            '@mitch/predicates',
            '@mitch/layer-resolver',
            '@mitch/oid4vp',
            '@mitch/data-flow',
            '@mitch/mdoc',
        ],
    },

    server: {
        port: 5174,
        strictPort: false,
        host: true,
        allowedHosts: true,
    },
});
