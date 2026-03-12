import { defineConfig } from 'vitest/config';

export default defineConfig({
    test: {
        environment: 'node',
        setupFiles: ['./test/setup.ts'],
        include: ['test/**/*.test.ts'],
        pool: 'forks',
        fileParallelism: false,
        hookTimeout: 30000,
        testTimeout: 30000,
    },
});
