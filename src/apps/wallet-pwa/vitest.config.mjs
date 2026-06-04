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
            '@askmi/policy-engine': path.resolve(__dirname, '../../packages/policy-engine/src'),
            '@askmi/audit-log': path.resolve(__dirname, '../../packages/audit-log/src'),
            '@askmi/secure-storage': path.resolve(__dirname, '../../packages/secure-storage/src'),
            '@askmi/predicates': path.resolve(__dirname, '../../packages/predicates/src'),
            '@askmi/oid4vp': path.resolve(__dirname, '../../packages/oid4vp/src'),
            '@askmi/mdoc': path.resolve(__dirname, '../../packages/mdoc/src'),
            '@askmi/data-flow': path.resolve(__dirname, '../../packages/data-flow/src'),
        },
    },
    test: {
        environment: 'jsdom',
        globals: true,
        setupFiles: ['./src/__tests__/setup.ts'],
    },
});
