import { defineConfig } from 'vitest/config';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  resolve: {
    alias: {
      '@mitch/shared-types': path.resolve(__dirname, '../shared-types/src'),
      '@mitch/shared-crypto': path.resolve(__dirname, '../shared-crypto/src'),
      '@mitch/layer-resolver': path.resolve(__dirname, '../layer-resolver/src'),
      '@mitch/predicates': path.resolve(__dirname, '../predicates/src'),
      '@mitch/mock-issuer': path.resolve(__dirname, '../mock-issuer/src'),
    },
  },
  test: {
    environment: 'node',
    include: ['src/__tests__/**/*.test.ts', 'tests/**/*.test.ts'],
    pool: 'threads',
    poolOptions: {
      threads: {
        singleThread: true,
      },
    },
  },
});
