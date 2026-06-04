import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
    plugins: [react()],
    resolve: {
        alias: {
            '@askmi/shared-types': path.resolve(__dirname, '../../packages/shared-types/src'),
            '@askmi/shared-crypto': path.resolve(__dirname, '../../packages/shared-crypto/src'),
            '@mitch/policy-engine': path.resolve(__dirname, '../../packages/policy-engine/src'),
            '@mitch/audit-log': path.resolve(__dirname, '../../packages/audit-log/src'),
            '@mitch/secure-storage': path.resolve(__dirname, '../../packages/secure-storage/src'),
            '@mitch/predicates': path.resolve(__dirname, '../../packages/predicates/src'),
            '@mitch/oid4vp': path.resolve(__dirname, '../../packages/oid4vp/src'),
            '@mitch/mdoc': path.resolve(__dirname, '../../packages/mdoc/src'),
            '@mitch/data-flow': path.resolve(__dirname, '../../packages/data-flow/src'),
        },
    },
    test: {
        environment: 'jsdom',
        globals: true,
        setupFiles: ['./src/__tests__/setup.ts'],
    },
});
