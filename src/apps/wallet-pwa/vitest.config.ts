import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig({
    plugins: [react()],
    resolve: {
        alias: {
            '@mitch/shared-types': path.resolve(__dirname, '../../packages/shared-types/src'),
            '@mitch/shared-crypto': path.resolve(__dirname, '../../packages/shared-crypto/src'),
            '@mitch/policy-engine': path.resolve(__dirname, '../../packages/policy-engine/src'),
            '@mitch/audit-log': path.resolve(__dirname, '../../packages/audit-log/src'),
            '@mitch/secure-storage': path.resolve(__dirname, '../../packages/secure-storage/src'),
            '@mitch/predicates': path.resolve(__dirname, '../../packages/predicates/src'),
        },
    },
    test: {
        environment: 'jsdom',
        globals: true,
        setupFiles: ['./src/__tests__/setup.ts'],
    },
});
