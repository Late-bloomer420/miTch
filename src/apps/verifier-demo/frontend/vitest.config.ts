import { defineConfig } from 'vitest/config';

// Node environment is sufficient: the current tests assert on static data
// fixtures and do not render React components.
export default defineConfig({
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts'],
  },
});
