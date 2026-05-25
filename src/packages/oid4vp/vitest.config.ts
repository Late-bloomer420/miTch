import { defineConfig } from 'vitest/config';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  resolve: {
    alias: {
      '@mitch/shared-crypto': path.resolve(__dirname, '../shared-crypto/src'),
      '@mitch/shared-types': path.resolve(__dirname, '../shared-types/src'),
    },
  },
  test: { environment: 'node', include: ['src/__tests__/**/*.test.ts'] },
});
